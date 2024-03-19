env:
	rustup install nightly-2023-05-01
	rustup default nightly-2023-05-01
	rustup target add riscv64imac-unknown-none-elf
	rustup component add rust-src
run:
	cargo build --release --target riscv64imac-unknown-none-elf