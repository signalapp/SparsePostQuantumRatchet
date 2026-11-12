# Runs ProVerif on each query file of `extraction-model/` and compares its
# RESULT lines with the file's `(* EXPECTPV ... END *)` block, ignoring the
# numbering of variables, which shifts with the declarations. `make update`
# rewrites the blocks instead.
#
# Needs `proverif` in PATH, `extraction/lib.pvl` (`./hax.py extract-proverif`)
# and hax's ProVerif libraries: set PROVERIF_LIBS to the `proof-libs/proverif`
# directory of the hax checkout providing `cargo-hax`.

SHELL := bash
.SHELLFLAGS := -o pipefail -c
.DELETE_ON_ERROR:

PROVERIF_LIBS ?= $(error Set PROVERIF_LIBS to hax's proof-libs/proverif directory)

MODEL := extraction-model
QUERIES := $(basename $(notdir $(wildcard $(MODEL)/*.pv)))

# `heal_*` and `chain_*` flag injected transcripts.
accept = $(if $(filter heal_% chain_%,$(1)),accept_injection,accept)
libs = $(PROVERIF_LIBS)/primitives.pvl $(PROVERIF_LIBS)/result.pvl \
	$(MODEL)/handwritten_lib.pvl extraction/lib.pvl $(MODEL)/nepochs.pvl \
	$(MODEL)/model.pvl $(MODEL)/$(call accept,$(1)).pvl $(MODEL)/roles.pvl

check: $(QUERIES:%=%.check)
update: $(QUERIES:%=%.update)

extraction/%.results: $(MODEL)/%.pv extraction/lib.pvl $(PROVERIF_LIBS)/primitives.pvl \
		$(PROVERIF_LIBS)/result.pvl $(wildcard $(MODEL)/*.pvl)
	proverif $(addprefix -lib ,$(call libs,$*)) $< | tee extraction/$*.log | grep '^RESULT' > $@

extraction/lib.pvl:
	$(error $@ not found: run ./hax.py extract-proverif)
$(PROVERIF_LIBS)/primitives.pvl $(PROVERIF_LIBS)/result.pvl:
	$(error $@ not found: set PROVERIF_LIBS to hax's proof-libs/proverif directory)

unnumber = sed -E 's/([A-Za-z])_[0-9]+/\1/g'

# One line per query: its expected and actual verdict, matched by query text.
%.check: extraction/%.results
	@awk -v f=$*.pv 'function v(l) { return l ~ /is true\.$$/ ? "true" : l ~ /is false\.$$/ ? "false" : "cannot be proved" } \
		function q(l) { sub(/^RESULT /, "", l); sub(/ (is true|is false|cannot be proved)\.$$/, "", l); return l } \
		function p(ok, ev, av, k) { bad += !ok; printf("%-4s %-22s expected %-5s got %-5s %s\n", ok ? "ok" : "FAIL", \
			f ":" ++i, ev, av, length(k) > 60 ? substr(k, 1, 57) "..." : k) } \
		FILENAME == ARGV[1] { k = q($$0); e[k] = v($$0); order[++n] = k; next } \
		{ k = q($$0); seen[k] = 1; p(k in e && e[k] == v($$0), k in e ? e[k] : "-", v($$0), k) } \
		END { for (j = 1; j <= n; j++) if (!(order[j] in seen)) p(0, e[order[j]], "-", order[j]); exit bad > 0 }' \
		<(sed -n '/^(\* EXPECTPV/,/^END \*)/p' $(MODEL)/$*.pv | grep '^RESULT' | $(unnumber)) \
		<($(unnumber) $<)

%.update: extraction/%.results
	awk -v r=$< '/^\(\* EXPECTPV/ { print; while ((getline l < r) > 0) print l; skip = 1; next } \
		/^END \*\)/ { skip = 0 } !skip' $(MODEL)/$*.pv > $<.pv && mv $<.pv $(MODEL)/$*.pv

.SECONDARY:
.PHONY: check update
