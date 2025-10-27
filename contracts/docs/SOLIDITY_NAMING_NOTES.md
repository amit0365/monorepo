# Solidity Naming Considerations

## The `view` Keyword Conflict

### Issue

When implementing the Simplex verifier in Solidity, we encountered a conflict with the `view` field from Rust's `Round(epoch, view)` type.

**Rust Definition:**
```rust
pub struct Round(pub Epoch, pub View);
// where Epoch = u64, View = u64
```

**Solidity Problem:**
```solidity
struct Round {
    uint64 epoch;
    uint64 view;  // ❌ Compiler error!
}
```

### Compiler Error

```
Error (9106): State mutability can only be specified for address types.
Struct Property: view
Struct: Round
Type Info: uint64
```

This error message is **misleading** - the real issue is that `view` is a reserved keyword in Solidity (used for function modifiers like `function foo() public view`).

While `view` technically CAN be used as a struct field name in some Solidity contexts, it causes compilation errors and IDE issues, making it problematic.

### Solution

Renamed to `viewCounter` throughout the contract:

```solidity
/// @notice Represents a Round in consensus (epoch, view)
/// @dev Matches Rust: pub struct Round(Epoch, View) where Epoch = u64, View = u64
/// @dev Note: Named 'viewCounter' instead of 'view' to avoid Solidity keyword conflict
struct Round {
    uint64 epoch;
    uint64 viewCounter;
}
```

### Usage

```solidity
// Creating a Round
Round memory r = Round({
    epoch: 1,
    viewCounter: 100
});

// Accessing view
uint64 v = r.viewCounter;

// Comparisons
if (round1.viewCounter == round2.viewCounter) {
    // same view
}
```

---

## Other Solidity Reserved Keywords to Watch

When mapping Rust types to Solidity, watch out for these reserved keywords:

### Common Conflicts

| Rust Name | Solidity Conflict | Recommended Alternative |
|-----------|-------------------|-------------------------|
| `view` | Function modifier | `viewCounter`, `viewNumber` |
| `type` | Reserved keyword | `type_`, `typeId` |
| `storage` | Reserved keyword | `storage_`, `storageSlot` |
| `memory` | Reserved keyword | `memory_`, `memSlot` |
| `calldata` | Reserved keyword | `calldata_`, `calldataOffset` |
| `address` | Type keyword | `address_`, `addr` |
| `payable` | Function modifier | `payable_`, `isPayable` |
| `constant` | State mutability | `constant_`, `isConstant` |
| `immutable` | State mutability | `immutable_`, `isImmutable` |

### Naming Conventions

When a Rust field name conflicts with Solidity keywords:

1. **Suffix with underscore or descriptive word**: `viewCounter`, `viewNumber`
2. **Use camelCase variation**: `viewId`, `typeId`
3. **Add context**: `roundView`, `messageType`

**Avoid:**
- Single underscore prefix: `_view` (reserved for internal functions)
- All caps: `VIEW` (reserved for constants)
- Abbreviations: `v` (unclear)

---

## Documentation Pattern

Always document naming deviations from Rust:

```solidity
/// @notice Represents X from Rust
/// @dev Matches Rust: pub struct X { ... }
/// @dev Note: Field 'foo' renamed to 'foo_field' to avoid Solidity keyword conflict
struct X {
    uint64 foo_field;
}
```

This helps future developers understand why the naming differs from the Rust implementation.

---

## Testing Considerations

When writing tests, the field names should match the contract:

```solidity
// ✅ Correct
assertEq(round.viewCounter, 100);

// ❌ Wrong
assertEq(round.view, 100);  // Compilation error
```

---

## Cross-Language Mapping Table

For Simplex types, here's the complete Rust → Solidity mapping:

| Rust Type | Rust Fields | Solidity Type | Solidity Fields | Notes |
|-----------|-------------|---------------|-----------------|-------|
| `Round` | `epoch`, `view` | `Round` | `epoch`, `viewCounter` | Renamed due to keyword |
| `Proposal` | `round`, `parent`, `payload` | `Proposal` | `round`, `parent`, `payload` | No changes |
| `Vote` | `signer`, `signature` | `Vote` | `signer`, `signature` | No changes |

---

## IDE Support

Most Solidity IDEs will:
- ✅ Correctly syntax-highlight `viewCounter` as a field name
- ⚠️ May incorrectly highlight `view` as a keyword even in struct context
- ✅ Provide better autocomplete for non-keyword names

This is another reason to use `viewCounter` instead of relying on context-dependent keyword parsing.

---

## Alternative Naming Options

If you want to change from `viewCounter`, here are ranked alternatives:

| Option | Pros | Cons | Verdict |
|--------|------|------|---------|
| `viewCounter` | Clear, explicit | Slightly verbose | ✅ **Current choice** |
| `viewNumber` | Follows Solidity conventions | More verbose | ✅ Good alternative |
| `viewId` | Short, clear | Not technically an ID | ⚠️ Okay |
| `view_` | Short, avoids keyword | Less conventional | ⚠️ Okay |
| `v` | Very short | Too abbreviated | ❌ Avoid |
| `vw` | Short | Unclear | ❌ Avoid |

**Recommendation:** Stick with `viewCounter` for consistency with underscore suffix pattern.

---

## Lessons Learned

1. **Always test compile early** when mapping external types to Solidity
2. **Document naming deviations** to avoid confusion
3. **Misleading error messages** - Solidity compiler errors aren't always clear about keyword conflicts
4. **Prefer explicit names** over trying to use keywords in context-dependent ways
5. **Consistency matters** - once you pick a naming convention, use it everywhere

---

## Related Issues

- Solidity doesn't allow certain keywords even in valid contexts
- Some keywords work in structs but fail in function parameters
- Error messages may not clearly indicate keyword conflicts
- Different Solidity versions may have different keyword restrictions

Always check the [Solidity documentation](https://docs.soliditylang.org/en/latest/grammar.html#keywords) for the complete list of reserved keywords.
