FROM docker.io/ubuntu:22.04

WORKDIR /app
ADD rust-toolchain.toml /app/
RUN apt-get update -y && DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt-get install -y curl msr-tools python3 python3-venv python3-pip m4 build-essential clang cmake libssl-dev texlive-full && apt-get clean -y
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
RUN curl -fsSL https://install.julialang.org | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
ENV PATH="/root/.juliaup/bin:${PATH}"

ADD requirements.txt /app/
RUN python3 -m venv venv && . venv/bin/activate && pip install -r requirements.txt

ADD src /app/src
ADD Cargo.toml Cargo.lock /app/
ADD liboqs-rust /app/liboqs-rust
RUN cargo build && cargo build --release

ADD nanoBench /app/nanoBench
ADD visualize /app/visualize
ADD *.jl pyproject.toml precomputation_128.json collect_* Manifest.toml Project.toml /app/

RUN julia --project=. -e 'using Pkg; Pkg.instantiate()'

ENV PATH="/app/venv/bin:$PATH"
RUN mkdir figures data
