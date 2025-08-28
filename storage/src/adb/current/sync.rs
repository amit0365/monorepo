use crate::{
    adb::{self, any::fixed, current, sync},
    index::Index,
    journal::fixed as fixed_journal,
    mmr::{
        bitmap::Bitmap,
        hasher::{Grafting, Standard},
        iterator::{leaf_num_to_pos, leaf_pos_to_num},
        verification::Proof as MmrProof,
    },
    store::operation::Fixed,
    translator::Translator,
};
use commonware_codec::{CodecFixed, Encode as _};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use std::num::NonZeroU64;

/// Wraps a [fixed_journal::Journal] to provide a sync-compatible interface for Current database.
/// The journal stores Fixed<K, V> operations, but the sync protocol uses Data<K, V, N> which
/// includes bitmap chunks.
pub struct Journal<E, K, V>
where
    E: Storage + Metrics,
    K: Array,
    V: CodecFixed<Cfg = ()>,
{
    /// Underlying fixed journal storing the operations.
    inner: fixed_journal::Journal<E, Fixed<K, V>>,
}

impl<E, K, V> Journal<E, K, V>
where
    E: Storage + Metrics,
    K: Array,
    V: CodecFixed<Cfg = ()>,
{
    /// Create a new sync-compatible [Journal].
    pub fn new(inner: fixed_journal::Journal<E, Fixed<K, V>>) -> Self {
        Self { inner }
    }

    /// Return the inner [fixed_journal::Journal].
    pub fn into_inner(self) -> fixed_journal::Journal<E, Fixed<K, V>> {
        self.inner
    }
}

impl<E, K, V> sync::Journal for Journal<E, K, V>
where
    E: Storage + Metrics,
    K: Array,
    V: CodecFixed<Cfg = ()> + Send + 'static,
{
    type Data = Fixed<K, V>;
    type Error = crate::journal::Error;

    async fn size(&self) -> Result<u64, Self::Error> {
        self.inner.size().await
    }

    async fn append(&mut self, data: Self::Data) -> Result<(), Self::Error> {
        // For Current database sync, data is a single operation
        self.inner.append(data).await?;
        Ok(())
    }

    async fn close(self) -> Result<(), Self::Error> {
        self.inner.close().await
    }
}

/// Proof data for Current database sync operations.
/// Contains both the MMR proof and the bitmap chunks needed for verification.
#[derive(Clone, Debug)]
pub struct Proof<D: commonware_cryptography::Digest, const N: usize> {
    /// The MMR proof for the operations
    pub proof: MmrProof<D>,
    /// The bitmap chunks needed to verify the proof
    pub chunks: Vec<[u8; N]>,
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: CodecFixed<Cfg = ()> + Clone + Send + Sync + 'static,
        H: Hasher,
        T: Translator + Send + Sync + 'static,
        const N: usize,
    > adb::sync::Database for current::Current<E, K, V, H, T, N>
where
    T::Key: Send + Sync,
{
    type Context = E;
    type Data = Fixed<K, V>;
    type Proof = Proof<H::Digest, N>;
    type PinnedNodes = Vec<H::Digest>;
    type Journal = Journal<E, K, V>;
    type Hasher = H;
    type Error = adb::Error;
    type Config = current::Config<T>;
    type Digest = H::Digest;

    async fn create_journal(
        context: Self::Context,
        config: &Self::Config,
        lower_bound: u64,
        upper_bound: u64,
    ) -> Result<Self::Journal, <Self::Journal as sync::Journal>::Error> {
        let journal_config = fixed_journal::Config {
            partition: config.log_journal_partition.clone(),
            items_per_blob: config.log_items_per_blob,
            write_buffer: config.log_write_buffer,
            buffer_pool: config.buffer_pool.clone(),
        };

        let inner_journal = fixed::sync::init_journal(
            context.with_label("log"),
            journal_config,
            lower_bound,
            upper_bound,
        )
        .await?;

        Ok(Journal::new(inner_journal))
    }

    async fn from_sync_result(
        context: Self::Context,
        db_config: Self::Config,
        log: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        lower_bound: u64,
        upper_bound: u64,
        apply_batch_size: usize,
    ) -> Result<Self, Self::Error> {
        let log = log.into_inner();
        // Initialize the MMR with sync configuration
        let mut mmr = crate::mmr::journaled::Mmr::init_sync(
            context.with_label("mmr"),
            crate::mmr::journaled::SyncConfig {
                config: crate::mmr::journaled::Config {
                    journal_partition: db_config.mmr_journal_partition,
                    metadata_partition: db_config.mmr_metadata_partition,
                    items_per_blob: db_config.mmr_items_per_blob,
                    write_buffer: db_config.mmr_write_buffer,
                    thread_pool: db_config.thread_pool.clone(),
                    buffer_pool: db_config.buffer_pool.clone(),
                },
                lower_bound: leaf_num_to_pos(lower_bound),
                upper_bound: leaf_num_to_pos(upper_bound + 1) - 1,
                pinned_nodes,
            },
        )
        .await
        .map_err(adb::Error::Mmr)?;

        // Convert MMR size to number of operations
        let Some(mmr_ops) = leaf_pos_to_num(mmr.size()) else {
            return Err(adb::Error::Mmr(crate::mmr::Error::InvalidSize(mmr.size())));
        };

        // Apply the missing operations from the log to the MMR
        let mut hasher = Standard::<H>::new();
        let log_size = log.size().await?;
        for i in mmr_ops..log_size {
            let op = log.read(i).await?;
            mmr.add_batched(&mut hasher, &op.encode()).await?;
            if i % apply_batch_size as u64 == 0 {
                mmr.sync(&mut hasher).await?;
            }
        }

        // Initialize the bitmap
        let mut status = Bitmap::restore_pruned(
            context.with_label("bitmap"),
            &db_config.bitmap_metadata_partition,
            db_config.thread_pool.clone(),
        )
        .await?;

        // Ensure consistency between the bitmap and the MMR
        let mmr_pruned_pos = mmr.pruned_to_pos();
        let mut start_leaf_num = leaf_pos_to_num(mmr_pruned_pos).unwrap();
        let bit_count = status.bit_count();
        if start_leaf_num < bit_count {
            start_leaf_num = bit_count;
        }

        let pruned_bits = status.pruned_bits();
        let bitmap_pruned_pos = leaf_num_to_pos(pruned_bits);
        let mmr_pruned_leaves = leaf_pos_to_num(mmr_pruned_pos).unwrap();

        let mut grafter = Grafting::new(
            &mut hasher,
            current::Current::<E, K, V, H, T, N>::grafting_height(),
        );
        if bitmap_pruned_pos < mmr_pruned_pos {
            let chunk_bits = Bitmap::<H, N>::CHUNK_SIZE_BITS;
            assert!(
                mmr_pruned_leaves <= chunk_bits || pruned_bits >= mmr_pruned_leaves - chunk_bits
            );
            for _ in pruned_bits..mmr_pruned_leaves {
                status.append(false);
            }
            grafter
                .load_grafted_digests(&status.dirty_chunks(), &mmr)
                .await?;
            status.sync(&mut grafter).await?;
        }

        // Build the snapshot from the log
        let mut snapshot =
            Index::init(context.with_label("snapshot"), db_config.translator.clone());
        let inactivity_floor_loc = fixed::Any::<E, K, V, H, T>::build_snapshot_from_log(
            start_leaf_num,
            &log,
            &mut snapshot,
            Some(&mut status),
        )
        .await?;

        grafter
            .load_grafted_digests(&status.dirty_chunks(), &mmr)
            .await?;
        status.sync(&mut grafter).await?;

        let target_prune_loc = inactivity_floor_loc.saturating_sub(db_config.pruning_delay);
        if target_prune_loc > start_leaf_num {
            mmr.prune_to_pos(grafter.standard(), leaf_num_to_pos(target_prune_loc))
                .await?;
        }

        let any = fixed::Any {
            mmr,
            log,
            snapshot,
            inactivity_floor_loc,
            uncommitted_ops: 0,
            hasher: Standard::<H>::new(),
            pruning_delay: db_config.pruning_delay,
        };

        let current = Self {
            any,
            status,
            context,
            bitmap_metadata_partition: db_config.bitmap_metadata_partition,
        };

        Ok(current)
    }

    fn root(&self) -> Self::Digest {
        let mut hasher = Standard::<H>::new();
        // TODO fix this
        futures::executor::block_on(async { self.root(&mut hasher).await.unwrap() })
    }

    async fn resize_journal(
        journal: Self::Journal,
        context: Self::Context,
        config: &Self::Config,
        lower_bound: u64,
        upper_bound: u64,
    ) -> Result<Self::Journal, Self::Error> {
        let mut inner_journal = journal.into_inner();
        let size = inner_journal.size().await.map_err(adb::Error::from)?;

        if size <= lower_bound {
            // Close the existing journal before creating a new one
            inner_journal.close().await.map_err(adb::Error::from)?;

            // Create a new journal with the new bounds
            Self::create_journal(context, config, lower_bound, upper_bound)
                .await
                .map_err(adb::Error::from)
        } else {
            // Just prune to the lower bound
            inner_journal
                .prune(lower_bound)
                .await
                .map_err(adb::Error::from)?;
            Ok(Journal::new(inner_journal))
        }
    }

    fn verify_proof(
        proof: &Self::Proof,
        data: &[Self::Data],
        start_loc: u64,
        root: Self::Digest,
    ) -> bool {
        let mut hasher = Standard::<H>::new();
        Self::verify_range_proof(
            &mut hasher,
            &proof.proof,
            start_loc,
            data,
            &proof.chunks,
            &root,
        )
    }

    fn extract_pinned_nodes(
        proof: &Self::Proof,
        start_loc: u64,
        data_len: u64,
    ) -> Result<Self::PinnedNodes, Self::Error> {
        let pinned_nodes = adb::extract_pinned_nodes(&proof.proof, start_loc, data_len)?;
        Ok(pinned_nodes)
    }
}

// Implement the Resolver trait for Current database
impl<E, K, V, H, T, const N: usize> sync::resolver::Resolver
    for std::sync::Arc<commonware_runtime::RwLock<current::Current<E, K, V, H, T, N>>>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: CodecFixed<Cfg = ()> + Clone + Send + Sync + 'static,
    H: Hasher,
    T: Translator + Send + Sync + 'static,
    T::Key: Send + Sync,
{
    type Digest = H::Digest;
    type Proof = Proof<H::Digest, N>;
    type Data = Fixed<K, V>;
    type Error = adb::Error;

    async fn get_data(
        &self,
        _size: u64,
        start_loc: u64,
        max_data: NonZeroU64,
    ) -> Result<sync::resolver::FetchResult<Self::Data, Self::Proof>, Self::Error> {
        let db = self.read().await;
        let mut hasher = H::new();

        let (proof, ops, chunks) = db
            .range_proof(&mut hasher, start_loc, max_data.get())
            .await?;

        let sync_proof = Proof { proof, chunks };

        let (success_tx, _success_rx) = futures::channel::oneshot::channel();

        Ok(sync::resolver::FetchResult {
            proof: sync_proof,
            data: ops,
            success_tx,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        adb::{
            current::{self, Config as CurrentConfig},
            sync::{self, engine::Config, Target},
        },
        mmr::{hasher::Standard, iterator::leaf_num_to_pos},
        store::operation::Fixed,
        translator::TwoCap,
    };
    use commonware_codec::FixedSize;
    use commonware_cryptography::{sha256::Digest, Digest as _, Sha256};
    use commonware_runtime::{
        buffer::PoolRef,
        deterministic::{self, Context},
        Runner as _,
    };
    use commonware_utils::{NZUsize, NZU64};
    use rand::{rngs::StdRng, RngCore as _, SeedableRng as _};
    use std::{
        collections::{HashMap, HashSet},
        num::NonZeroU64,
        sync::Arc,
    };
    use test_case::test_case;

    const SHA256_SIZE: usize = <Sha256 as commonware_cryptography::Hasher>::Digest::SIZE;
    const PAGE_SIZE: usize = 77;
    const PAGE_CACHE_SIZE: usize = 9;

    fn test_hasher() -> Standard<Sha256> {
        Standard::<Sha256>::new()
    }

    /// A type alias for the concrete [Current] type used in these unit tests.
    type CurrentTest =
        current::Current<deterministic::Context, Digest, Digest, Sha256, TwoCap, SHA256_SIZE>;

    fn create_test_config(seed: u64) -> CurrentConfig<TwoCap> {
        CurrentConfig {
            mmr_journal_partition: format!("mmr_journal_{seed}"),
            mmr_metadata_partition: format!("mmr_metadata_{seed}"),
            mmr_items_per_blob: NZU64!(1024),
            mmr_write_buffer: NZUsize!(64),
            log_journal_partition: format!("log_journal_{seed}"),
            log_items_per_blob: NZU64!(1024),
            log_write_buffer: NZUsize!(64),
            bitmap_metadata_partition: format!("bitmap_metadata_{seed}"),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            pruning_delay: 10,
        }
    }

    /// Create a test database with unique partition names
    async fn create_test_db(mut context: Context) -> CurrentTest {
        let seed = context.next_u64();
        let config = create_test_config(seed);
        CurrentTest::init(context, config).await.unwrap()
    }

    /// Create n random operations. Some portion of the updates are deletes.
    /// create_test_ops(n') is a suffix of create_test_ops(n) for n' > n.
    fn create_test_ops(n: usize) -> Vec<Fixed<Digest, Digest>> {
        let mut rng = StdRng::seed_from_u64(1337);
        let mut prev_key = Digest::random(&mut rng);
        let mut ops = Vec::new();
        for i in 0..n {
            let key = Digest::random(&mut rng);
            if i % 10 == 0 && i > 0 {
                ops.push(Fixed::Delete(prev_key));
            } else {
                let value = Digest::random(&mut rng);
                ops.push(Fixed::Update(key, value));
                prev_key = key;
            }
        }
        ops
    }

    /// Applies the given operations to the database.
    async fn apply_ops(db: &mut CurrentTest, ops: Vec<Fixed<Digest, Digest>>) {
        for op in ops {
            match op {
                Fixed::Update(key, value) => {
                    db.update(key, value).await.unwrap();
                }
                Fixed::Delete(key) => {
                    db.delete(key).await.unwrap();
                }
                Fixed::CommitFloor(_) => {
                    db.commit().await.unwrap();
                }
            }
        }
    }

    #[test_case(1, NZU64!(1); "singleton db with batch size == 1")]
    #[test_case(1, NZU64!(2); "singleton db with batch size > db size")]
    #[test_case(1000, NZU64!(1); "db with batch size 1")]
    #[test_case(1000, NZU64!(3); "db size not evenly divided by batch size")]
    #[test_case(1000, NZU64!(999); "db size not evenly divided by batch size; different batch size")]
    #[test_case(1000, NZU64!(100); "db size divided by batch size")]
    #[test_case(1000, NZU64!(1000); "db size == batch size")]
    #[test_case(1000, NZU64!(1001); "batch size > db size")]
    fn test_sync(target_db_ops: usize, fetch_batch_size: NonZeroU64) {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut target_db = create_test_db(context.clone()).await;
            let target_db_ops = create_test_ops(target_db_ops);
            apply_ops(&mut target_db, target_db_ops.clone()).await;
            target_db.commit().await.unwrap();
            let target_op_count = target_db.op_count();
            let target_inactivity_floor = target_db.any.inactivity_floor_loc;
            let target_log_size = target_db.any.log.size().await.unwrap();
            let mut hasher = test_hasher();
            let target_root = target_db.root(&mut hasher).await.unwrap();

            // After commit, the database may have pruned early operations
            // Start syncing from the inactivity floor, not 0
            let lower_bound = target_db.any.inactivity_floor_loc;

            // Capture target database state and deleted keys before moving into config
            let mut expected_kvs = HashMap::new();
            let mut deleted_keys = HashSet::new();
            for op in &target_db_ops {
                match op {
                    Fixed::Update(key, _) => {
                        if let Some((value, loc)) = target_db.any.get_key_loc(key).await.unwrap() {
                            expected_kvs.insert(*key, (value, loc));
                            deleted_keys.remove(key);
                        }
                    }
                    Fixed::Delete(key) => {
                        expected_kvs.remove(key);
                        deleted_keys.insert(*key);
                    }
                    Fixed::CommitFloor(_) => {
                        // Ignore
                    }
                }
            }

            let db_config = create_test_config(context.next_u64());

            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = Config {
                db_config: db_config.clone(),
                fetch_batch_size,
                target: Target {
                    root: target_root,
                    lower_bound,
                    upper_bound: target_op_count - 1, // target_op_count is the count, operations are 0-indexed
                },
                context: context.clone(),
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: None,
            };
            let mut got_db: CurrentTest = sync::sync(config).await.unwrap();

            // Verify database state
            let mut hasher = test_hasher();
            assert_eq!(got_db.op_count(), target_op_count);
            assert_eq!(got_db.any.inactivity_floor_loc, target_inactivity_floor);
            assert_eq!(got_db.any.log.size().await.unwrap(), target_log_size);
            assert_eq!(
                got_db.any.mmr.pruned_to_pos(),
                leaf_num_to_pos(target_inactivity_floor)
            );

            // Verify the root digest matches the target
            assert_eq!(got_db.root(&mut hasher).await.unwrap(), target_root);

            // Verify that the synced database matches the target state
            for (key, &(value, loc)) in &expected_kvs {
                let synced_opt = got_db.any.get_key_loc(key).await.unwrap();
                assert_eq!(synced_opt, Some((value, loc)));
            }
            // Verify that deleted keys are absent
            for key in &deleted_keys {
                assert!(got_db.any.get_key_loc(key).await.unwrap().is_none(),);
            }

            // Put more key-value pairs into both databases
            let mut new_ops = Vec::new();
            let mut rng = StdRng::seed_from_u64(42);
            let mut new_kvs = HashMap::new();
            for _ in 0..expected_kvs.len() {
                let key = Digest::random(&mut rng);
                let value = Digest::random(&mut rng);
                new_ops.push(Fixed::Update(key, value));
                new_kvs.insert(key, value);
            }
            apply_ops(&mut got_db, new_ops.clone()).await;
            apply_ops(&mut *target_db.write().await, new_ops).await;
            got_db.commit().await.unwrap();
            target_db.write().await.commit().await.unwrap();

            // Verify that the databases match
            for (key, value) in &new_kvs {
                let got_value = got_db.get(key).await.unwrap().unwrap();
                let target_value = target_db.read().await.get(key).await.unwrap().unwrap();
                assert_eq!(got_value, target_value);
                assert_eq!(got_value, *value);
            }

            let final_target_root = target_db.write().await.root(&mut hasher).await.unwrap();
            assert_eq!(got_db.root(&mut hasher).await.unwrap(), final_target_root);

            // Capture the database state before closing
            let final_synced_op_count = got_db.op_count();
            let final_synced_inactivity_floor = got_db.any.inactivity_floor_loc;
            let final_synced_log_size = got_db.any.log.size().await.unwrap();
            let final_synced_oldest_retained_loc = got_db.oldest_retained_loc();
            let final_synced_pruned_to_pos = got_db.any.mmr.pruned_to_pos();
            let final_synced_root = got_db.root(&mut hasher).await.unwrap();

            // Close both databases
            got_db.close().await.unwrap();
            let target_db_owned = match Arc::try_unwrap(target_db) {
                Ok(rwlock) => rwlock.into_inner(),
                Err(_) => panic!("Failed to unwrap Arc - multiple references exist"),
            };
            target_db_owned.close().await.unwrap();

            // Reopen the synced database and verify it retains its state
            let reopened_db = CurrentTest::init(context.clone(), db_config).await.unwrap();
            assert_eq!(reopened_db.op_count(), final_synced_op_count);
            assert_eq!(
                reopened_db.any.inactivity_floor_loc,
                final_synced_inactivity_floor
            );
            assert_eq!(
                reopened_db.any.log.size().await.unwrap(),
                final_synced_log_size
            );
            assert_eq!(
                reopened_db.oldest_retained_loc(),
                final_synced_oldest_retained_loc
            );
            assert_eq!(
                reopened_db.any.mmr.pruned_to_pos(),
                final_synced_pruned_to_pos
            );
            assert_eq!(
                reopened_db.root(&mut hasher).await.unwrap(),
                final_synced_root
            );

            // Verify the key-value pairs are still correct
            for (key, value) in &new_kvs {
                let reopened_value = reopened_db.get(key).await.unwrap().unwrap();
                assert_eq!(reopened_value, *value);
            }
        });
    }
}
