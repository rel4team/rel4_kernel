env:
	rustup install nightly
	rustup default nightly
	rustup target add riscv64imac-unknown-none-elf
run:
	cargo build --release --target riscv64imac-unknown-none-elf