from z3 import *

s = Solver()

# --- State variables for _removeNft ---
# nfts array modeled as a sequence of (nftContract, tokenId) pairs.
# We model the array as a list of Z3 expressions. Since Z3 doesn't have
# dynamic arrays, we fix a maximum length (e.g., 4) and use a length variable.
# We'll model the array contents as two arrays: nftContract_0[i], tokenId_0[i]
# for the initial state, and nftContract_1[i], tokenId_1[i] for the final state.
# We'll use a length variable len_0 and len_1.

# Maximum array length to model (small for tractability)
MAX_LEN = 4

# Initial state arrays
nftContract_0 = [BitVec(f'nftContract_0_{i}', 256) for i in range(MAX_LEN)]
tokenId_0 = [BitVec(f'tokenId_0_{i}', 256) for i in range(MAX_LEN)]
len_0 = BitVec('len_0', 256)

# Final state arrays (after _removeNft)
nftContract_1 = [BitVec(f'nftContract_1_{i}', 256) for i in range(MAX_LEN)]
tokenId_1 = [BitVec(f'tokenId_1_{i}', 256) for i in range(MAX_LEN)]
len_1 = BitVec('len_1', 256)

# Parameters to _removeNft
nftContract = BitVec('nftContract', 256)
tokenId = BitVec('tokenId', 256)

# --- Bounds ---
# Constrain lengths to small values
s.add(ULE(len_0, BitVecVal(MAX_LEN, 256)))
s.add(UGE(len_0, BitVecVal(0, 256)))

# Constrain addresses and tokenIds to small ranges for tractability
for i in range(MAX_LEN):
    s.add(ULE(nftContract_0[i], BitVecVal(10, 256)))
    s.add(ULE(tokenId_0[i], BitVecVal(100, 256)))
s.add(ULE(nftContract, BitVecVal(10, 256)))
s.add(ULE(tokenId, BitVecVal(100, 256)))

# --- Model _removeNft semantics ---
# The function iterates over the array, finds the FIRST index where
# (nftContract == nftContract_0[i] && tokenId == tokenId_0[i]),
# then removes that element (swap-with-last + pop) and breaks.
# We need to encode this precisely.

# We'll use a "found" flag and an index variable.
# Since we can't have loops, we'll encode the semantics with a series of
# conditional expressions. We'll use a symbolic index `removeIndex` that
# represents the first matching index, or a sentinel value (e.g., len_0) if none.

# First, find the first matching index.
# We'll use a helper: for each i, define a boolean `match_i` = (nftContract == nftContract_0[i] && tokenId == tokenId_0[i])
match = [And(nftContract == nftContract_0[i], tokenId == tokenId_0[i]) for i in range(MAX_LEN)]

# Define `firstMatchIndex` as the smallest i where match_i is true, or len_0 if none.
# We'll encode this with a series of If-then-else expressions.
# We'll build it iteratively.
firstMatchIndex = BitVecVal(MAX_LEN, 256)  # sentinel: no match
for i in range(MAX_LEN - 1, -1, -1):
    firstMatchIndex = If(match[i], BitVecVal(i, 256), firstMatchIndex)

# Now, the removal logic:
# If firstMatchIndex < len_0 (i.e., a match exists), then:
#   - If firstMatchIndex != len_0 - 1, then nfts[firstMatchIndex] = nfts[len_0 - 1]
#   - pop() -> len_1 = len_0 - 1
#   - The element at the last position is removed.
# If no match, len_1 = len_0 and array unchanged.

# We'll encode the final state arrays element-wise.
# For each position i in the final array:
#   - If no match (firstMatchIndex >= len_0): nftContract_1[i] = nftContract_0[i], tokenId_1[i] = tokenId_0[i]
#   - If match exists:
#       - If i == firstMatchIndex: the element is replaced by the last element (if firstMatchIndex != len_0-1), else it's removed.
#       - If i == len_0 - 1 and firstMatchIndex != len_0 - 1: this element is removed (popped).
#       - Otherwise: unchanged.

# To simplify, we'll encode the final array as follows:
# We'll define a "removed" flag: removed = firstMatchIndex < len_0
removed = ULT(firstMatchIndex, len_0)

# For each position i in the final array (0 <= i < len_1):
# We need to determine what value it holds.
# The final array is the initial array with the element at firstMatchIndex removed
# (and the last element moved to firstMatchIndex if firstMatchIndex != len_0-1).

# We'll encode this with a series of constraints. Since we have a fixed MAX_LEN,
# we can enumerate all possible positions.

# First, constrain len_1:
s.add(len_1 == If(removed, len_0 - 1, len_0))

# Now, for each i in 0..MAX_LEN-1, we need to constrain nftContract_1[i] and tokenId_1[i].
# But we only care about positions i < len_1. For i >= len_1, the values are irrelevant.
# We'll add constraints for all i, but only enforce them when i < len_1.

for i in range(MAX_LEN):
    # Case 1: No match (removed == False)
    #   nftContract_1[i] == nftContract_0[i], tokenId_1[i] == tokenId_0[i]
    # Case 2: Match exists (removed == True)
    #   Sub-case A: i == firstMatchIndex and firstMatchIndex != len_0 - 1
    #       -> nftContract_1[i] == nftContract_0[len_0 - 1], tokenId_1[i] == tokenId_0[len_0 - 1]
    #   Sub-case B: i == firstMatchIndex and firstMatchIndex == len_0 - 1
    #       -> this element is removed, so i >= len_1 (we don't constrain it)
    #   Sub-case C: i == len_0 - 1 and firstMatchIndex != len_0 - 1
    #       -> this element is removed, so i >= len_1 (we don't constrain it)
    #   Sub-case D: otherwise (i != firstMatchIndex and i != len_0 - 1)
    #       -> nftContract_1[i] == nftContract_0[i], tokenId_1[i] == tokenId_0[i]

    # We'll use If-then-else to encode this.
    # Note: we need to be careful with the case where i >= len_1; we don't constrain those.

    # We'll build the constraint for position i:
    # If i < len_1, then:
    #   If not removed: value = original
    #   Else (removed):
    #     If i == firstMatchIndex:
    #       If firstMatchIndex != len_0 - 1: value = last element
    #       Else: (this shouldn't happen because i < len_1 and len_1 = len_0 - 1, so i can't be len_0-1)
    #     Else if i == len_0 - 1: (this shouldn't happen because i < len_1 = len_0 - 1)
    #     Else: value = original

    # Let's encode this more carefully.
    # We'll define the condition for "i is a valid position in the final array":
    valid_pos = ULT(BitVecVal(i, 256), len_1)

    # The value at position i in the final array:
    # We'll compute it symbolically.
    # If not removed: value = original[i]
    # If removed:
    #   If i == firstMatchIndex:
    #     If firstMatchIndex != len_0 - 1: value = original[len_0 - 1]
    #     Else: (i == len_0 - 1, but i < len_1 = len_0 - 1, so this is impossible; we can leave unconstrained)
    #   Else: value = original[i]

    # We'll build the expression for the final value at position i.
    # Note: we need to handle the case where len_0 - 1 might be out of bounds for the array,
    # but since len_0 <= MAX_LEN, len_0 - 1 is a valid index (0 to MAX_LEN-1).

    # Compute the "last index" value: we need to select from the original array at index len_0 - 1.
    # We'll use a series of If-then-else to select the element at index len_0 - 1.
    last_idx = len_0 - 1
    # Select nftContract_0[last_idx]
    last_nftContract = BitVecVal(0, 256)
    last_tokenId = BitVecVal(0, 256)
    for j in range(MAX_LEN):
        last_nftContract = If(last_idx == BitVecVal(j, 256), nftContract_0[j], last_nftContract)
        last_tokenId = If(last_idx == BitVecVal(j, 256), tokenId_0[j], last_tokenId)

    # Now compute the final value at position i.
    # We'll use a nested If.
    # Condition: i == firstMatchIndex
    cond_i_is_match = (BitVecVal(i, 256) == firstMatchIndex)

    # Condition: firstMatchIndex != len_0 - 1
    cond_not_last = (firstMatchIndex != last_idx)

    # Final value:
    final_nftContract_i = If(
        removed,
        If(
            cond_i_is_match,
            If(cond_not_last, last_nftContract, nftContract_0[i]),  # if match and not last, use last; else (match and last) shouldn't happen
            nftContract_0[i]  # not the match index, keep original
        ),
        nftContract_0[i]  # not removed, keep original
    )
    final_tokenId_i = If(
        removed,
        If(
            cond_i_is_match,
            If(cond_not_last, last_tokenId, tokenId_0[i]),
            tokenId_0[i]
        ),
        tokenId_0[i]
    )

    # Now constrain: if i < len_1, then nftContract_1[i] == final_nftContract_i, etc.
    s.add(Implies(valid_pos, nftContract_1[i] == final_nftContract_i))
    s.add(Implies(valid_pos, tokenId_1[i] == final_tokenId_i))

# --- Now encode the property to test ---
# The intent: "Duplicate NFT records are not fully removed. _removeNft breaks after the first matching
# (nftContract, tokenId), so a second stale duplicate remains in nfts after the physical NFT has left the vault."
# The property to test: if there are at least two duplicates of (nftContract, tokenId) in the initial array,
# then after _removeNft, at least one duplicate still remains.

# We need to check: does there exist a state where the initial array has >= 2 duplicates of (nftContract, tokenId),
# and after _removeNft, the final array still contains at least one (nftContract, tokenId)?

# First, let's define a helper: count the number of occurrences of (nftContract, tokenId) in the initial array.
# We'll use a symbolic count.
count_0 = BitVecVal(0, 256)
for i in range(MAX_LEN):
    count_0 = If(match[i], count_0 + 1, count_0)

# Similarly, count in the final array.
# We need to count occurrences in the final array, but only for positions < len_1.
count_1 = BitVecVal(0, 256)
for i in range(MAX_LEN):
    # Check if position i is valid and matches
    valid_pos_i = ULT(BitVecVal(i, 256), len_1)
    match_1_i = And(nftContract_1[i] == nftContract, tokenId_1[i] == tokenId)
    count_1 = If(And(valid_pos_i, match_1_i), count_1 + 1, count_1)

# --- Sanity probe: base model must be satisfiable ---
s.push()
print("SANITY:", s.check())
s.pop()

# --- Now test the property ---
# We want to find a counterexample where:
# - Initial array has at least 2 duplicates of (nftContract, tokenId)
# - Final array still has at least 1 duplicate

# Add the precondition: at least 2 duplicates initially
s.add(UGE(count_0, BitVecVal(2, 256)))

# Add the violation: at least 1 duplicate remains in the final array
s.add(UGE(count_1, BitVecVal(1, 256)))

# Check if this is satisfiable
result = s.check()
if result == sat:
    print("BUG FOUND: duplicate NFT remains after _removeNft")
    m = s.model()
    print("Initial length:", m[len_0])
    print("Final length:", m[len_1])
    print("nftContract:", m[nftContract])
    print("tokenId:", m[tokenId])
    print("Initial array:")
    for i in range(MAX_LEN):
        if m.eval(ULT(BitVecVal(i, 256), len_0)):
            print(f"  [{i}]: nftContract={m[nftContract_0[i]]}, tokenId={m[tokenId_0[i]]}")
    print("Final array:")
    for i in range(MAX_LEN):
        if m.eval(ULT(BitVecVal(i, 256), len_1)):
            print(f"  [{i}]: nftContract={m[nftContract_1[i]]}, tokenId={m[tokenId_1[i]]}")
else:
    print("Property holds: no duplicate remains after _removeNft")