PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
KEY_BITS ?= 2048
KEY_DIR ?= keys
ALT_KEY_DIR ?= keys2
INPUT_FILE ?= doc.txt
PACKAGE_FILE ?= doc.sig.json
CIPHERTEXT_FILE ?= doc.enc
DECRYPTED_FILE ?= doc.dec.txt

PUBLIC_KEY := $(KEY_DIR)/public.pem
PRIVATE_KEY := $(KEY_DIR)/private.pem
ALT_PUBLIC_KEY := $(ALT_KEY_DIR)/public.pem

.DEFAULT_GOAL := help
.PHONY: all help test keys keygen sign verify encrypt decrypt tamper clean
.ONESHELL:
.SILENT:

all: test sign verify encrypt decrypt tamper

help:
	printf '%s\n' \
		'Available targets:' \
		'  make test       Run the complete pytest suite' \
		'  make keygen     Generate or overwrite the keys in $(KEY_DIR)/' \
		'  make sign       Sign $(INPUT_FILE) into $(PACKAGE_FILE)' \
		'  make verify     Verify $(PACKAGE_FILE) with $(PUBLIC_KEY)' \
		'  make encrypt    Encrypt $(INPUT_FILE) into $(CIPHERTEXT_FILE)' \
		'  make decrypt    Decrypt $(CIPHERTEXT_FILE) into $(DECRYPTED_FILE)' \
		'  make tamper     Demonstrate verification failure with $(ALT_PUBLIC_KEY)' \
		'  make all        Run tests and the complete demonstration workflow' \
		'  make clean      Remove generated encryption/decryption files'

test:
	$(PYTHON) -m pytest -q

keys:
	if [ ! -f "$(PUBLIC_KEY)" ] || [ ! -f "$(PRIVATE_KEY)" ]; then
		$(PYTHON) main.py keygen --out-dir "$(KEY_DIR)" --bits "$(KEY_BITS)"
	fi

keygen:
	$(PYTHON) main.py keygen --out-dir "$(KEY_DIR)" --bits "$(KEY_BITS)" --force

sign: keys
	$(PYTHON) main.py sign \
		--key "$(PRIVATE_KEY)" \
		--pub "$(PUBLIC_KEY)" \
		--file "$(INPUT_FILE)" \
		--out "$(PACKAGE_FILE)" \
		--force

verify: keys
	$(PYTHON) main.py verify \
		--pub "$(PUBLIC_KEY)" \
		--package "$(PACKAGE_FILE)"

encrypt: keys
	$(PYTHON) main.py encrypt \
		--pub "$(PUBLIC_KEY)" \
		--in "$(INPUT_FILE)" \
		--out "$(CIPHERTEXT_FILE)" \
		--force

decrypt: keys
	rm -f "$(DECRYPTED_FILE)"
	$(PYTHON) main.py decrypt \
		--key "$(PRIVATE_KEY)" \
		--in "$(CIPHERTEXT_FILE)" \
		--out "$(DECRYPTED_FILE)"
	cmp -- "$(INPUT_FILE)" "$(DECRYPTED_FILE)"
	printf '%s\n' 'Decryption check: original and decrypted files are identical.'

tamper: keys
	if $(PYTHON) main.py verify \
		--pub "$(ALT_PUBLIC_KEY)" \
		--package "$(PACKAGE_FILE)"; then
		printf '%s\n' 'ERROR: verification unexpectedly succeeded with the wrong key.'
		exit 1
	else
		printf '%s\n' 'Tampering detected: verification failed with the wrong public key.'
	fi

clean:
	rm -f -- "$(CIPHERTEXT_FILE)" "$(DECRYPTED_FILE)"