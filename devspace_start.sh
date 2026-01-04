#!/bin/bash
set +e # Continue on errors

COLOR_BLUE="\033[0;94m"
COLOR_GREEN="\033[0;92m"
COLOR_RESET="\033[0m"

# echo -e "${COLOR_BLUE}"
# echo ">>> Installing OS Dependencies"
# echo -e "${COLOR_RESET}"
# apt-get update &&
# 	apt-get install -y --no-install-recommends python3 python3-pip g++ build-essential git libsqlite3-dev postgresql-client libkrb5-dev gcc openssl libssh2-1-dev make &&
# 	rm -rf /var/lib/apt/lists/*

# pip3 install mkdocs-techdocs-core mkdocs-material mkdocs-minify-plugin --break-system-packages

# echo -e "${COLOR_BLUE}"
# echo ">>> Installing Yarn Dependencies"
# echo -e "${COLOR_RESET}"
# echo y | yarn install

echo "x86_64-unknown-linux-gnu" > /target.txt
echo "-C linker=x86_64-linux-gnu-gcc" > /flags.txt

cargo chef prepare --recipe-path /recipe.json

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -yq --no-install-recommends build-essential libclang-19-dev \
    g++-aarch64-linux-gnu binutils-aarch64-linux-gnu \
    g++-x86-64-linux-gnu binutils-x86-64-linux-gnu

export RUSTFLAGS="$(cat /flags.txt)"
echo 'yes' | cargo chef cook --target "$(cat /target.txt)" --release --no-default-features --features "sqlite postgres mysql rocks s3 redis azure nats enterprise" --recipe-path /recipe.json

cargo build --target "$(cat /target.txt)" --release -p stalwart --no-default-features --features "sqlite postgres mysql rocks s3 redis azure nats enterprise"
cargo build --target "$(cat /target.txt)" --release -p stalwart-cli

mv "/build/target/$(cat /target.txt)/release" "/output"
apt-get install -yq --no-install-recommends ca-certificates
cp -R /output/stalwart /usr/local/bin
cp -R /output/stalwart-cli /usr/local/bin
cp ./resources/docker/entrypoint.sh /usr/local/bin/entrypoint.sh
chmod -R 755 /usr/local/bin

# Print useful output for user
echo -e "${COLOR_BLUE}
     %########%
     %###########%       ____                 _____
         %#########%    |  _ \   ___ __   __ / ___/  ____    ____   ____ ___
         %#########%    | | | | / _ \\\\\ \ / / \___ \ |  _ \  / _  | / __// _ \\
     %#############%    | |_| |(  __/ \ V /  ____) )| |_) )( (_| |( (__(  __/
     %#############%    |____/  \___|  \_/   \____/ |  __/  \__,_| \___\\\\\___|
 %###############%                                  |_|
 %###########%${COLOR_RESET}


Welcome to your development container!

This is how you can work with it:
- Files will be synchronized between your local machine and this container
- Some ports will be forwarded, so you can access this container via localhost
- Run \`${COLOR_GREEN}$ sh /usr/local/bin/entrypoint.sh ${COLOR_RESET}\` to start the application
- Or use the binary \`${COLOR_GREEN}/usr/local/bin/stalwart${COLOR_RESET}\`  and \`${COLOR_GREEN}/usr/local/bin/stalwart-cli${COLOR_RESET}\`
"

# Set terminal prompt
export PS1="\[${COLOR_BLUE}\]devspace\[${COLOR_RESET}\] ./\W \[${COLOR_BLUE}\]\\$\[${COLOR_RESET}\] "
if [ -z "$BASH" ]; then export PS1="$ "; fi

# Include project's bin/ folder in PATH
export PATH="./bin:$PATH"

# Open shell
bash --norc
