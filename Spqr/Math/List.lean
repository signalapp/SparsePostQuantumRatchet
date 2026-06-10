/-
Copyright 2026 The Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE-APACHE.
Authors: Hoang Le Truong
-/
import Spqr.Math.Poly.Coeff.ListOps
import Spqr.Math.Poly.CharTwo.ToGF216
import Spqr.Math.Poly.Eval
import Spqr.Math.Poly.Lagrange.InterpolantSum
import Spqr.Math.Poly.Horner.Eval
import Spqr.Math.Poly.ExpectedTrailing.Basic
import Spqr.Math.Poly.Identities.Basic

/-!
# General-purpose utility results

General-purpose utility lemmas (list indexing, arithmetic identities) used throughout the
polynomial specification proofs in `Spqr/Specs/Encoding/Polynomial`. These results are
independent of both Mathlib-specific algebra and Aeneas-extracted types.

## Main statements

### List indexing utilities
* `list_get_of_getElem?_eq`: if `xs[k]? = ys[k]?` and both are in bounds,
  then `xs.get k = ys.get k`.
* `getElem_bang_eq`: if `xs[k]? = ys[k]?` and both are in bounds, then `xs[k]! = ys[k]!`.
* `list_get_drop_eq`: `(l.drop n).get ⟨k, hk⟩ = l.get ⟨n + k, _⟩`.
* `list_getElem_bang_set_self`: `(l.set n x)[n]! = x` when `n < l.length`.
* `list_double_set_getElem_fst`: reading position `i` after setting at `i` then `j ≠ i`.
* `list_getElem?_getD_eq_getElem`: `xs[n]?.getD default = xs[n]` when `n < xs.length`.
* `getElem?_append_of_lt`: `(l₁ ++ l₂)[i]? = l₁[i]?` when `i < l₁.length`.-/



/-! ## List indexing utilities -/

/-- If `xs[k]? = ys[k]?` and both `k` are in bounds, then `xs.get k = ys.get k`. -/
theorem list_get_of_getElem?_eq {T : Type} {xs ys : List T}
    {k : Nat}
    (h : xs[k]? = ys[k]?) (hx : k < xs.length) (hy : k < ys.length) :
    xs.get ⟨k, hx⟩ = ys.get ⟨k, hy⟩ := by
  have h1 : xs[k]? = some (xs.get ⟨k, hx⟩) := List.getElem?_eq_getElem hx
  have h2 : ys[k]? = some (ys.get ⟨k, hy⟩) := List.getElem?_eq_getElem hy
  rw [h1, h2] at h
  exact Option.some_injective _ h

/-- If `xs[k]? = ys[k]?` and both `k` are in bounds, then `xs[k]! = ys[k]!`. -/
theorem getElem_bang_eq {T : Type} [Inhabited T] {xs ys : List T} {k : Nat}
    (h : xs[k]? = ys[k]?)
    (hx : k < xs.length) (hy : k < ys.length) :
    xs[k]! = ys[k]! := by
  rw [getElem!_pos xs k hx, getElem!_pos ys k hy]
  exact list_get_of_getElem?_eq h hx hy

/-- Drop indexing: `(l.drop n).get ⟨k, hk⟩ = l.get ⟨n + k, _⟩`. -/
theorem list_get_drop_eq {α : Type*} (l : List α) (n k : Nat)
    (hk : k < (l.drop n).length) :
    (l.drop n).get ⟨k, hk⟩ =
      l.get ⟨n + k, by rw [List.length_drop] at hk; omega⟩ := by
  simp only [List.get_eq_getElem, List.getElem_drop]

/-- `(l.set n x)[n]! = x` when `n < l.length`. -/
theorem list_getElem_bang_set_self {α : Type*} [Inhabited α]
    (l : List α) (n : Nat) (x : α) (hn : n < l.length) :
    (l.set n x)[n]! = x := by
  have h : n < (l.set n x).length := by rw [List.length_set]; exact hn
  rw [getElem!_pos (l.set n x) n h, List.getElem_set_self]

/-- Reading position `i` after setting at both `i` and `j ≠ i` gives the value set at `i`. -/
theorem list_double_set_getElem_fst {T : Type} {xs : List T} {i j : Nat} {a b : T}
    (hij : j ≠ i) {h : i < ((xs.set i a).set j b).length} :
    ((xs.set i a).set j b)[i]'h = a := by
  simp [hij]

/-- `xs[n]?.getD default = xs[n]` when `n < xs.length`. -/
theorem list_getElem?_getD_eq_getElem {T : Type} [Inhabited T] {xs : List T} {n : Nat}
    (h : n < xs.length) : xs[n]?.getD default = xs[n] := by
  simp [List.getElem?_eq_getElem h]

/-- `(l₁ ++ l₂)[i]? = l₁[i]?` when `i < l₁.length`. -/
theorem getElem?_append_of_lt {α : Type}
    (l₁ l₂ : List α) {i : Nat} (h : i < l₁.length) :
    (l₁ ++ l₂)[i]? = l₁[i]? := by
  simp [List.getElem?_append_left h]
