env:
	rustup install nightly-2024-01-31
	rustup default nightly-2024-01-31
	rustup target add riscv64imac-unknown-none-elf
	rustup component add rust-src
run:
	cargo build --release --target riscv64imac-unknown-none-elf