FROM node:18

WORKDIR /test/

ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD true

RUN apt-get update && apt-get install gnupg wget -y && \
  wget --quiet --output-document=- https://dl-ssl.google.com/linux/linux_signing_key.pub | gpg --dearmor > /etc/apt/trusted.gpg.d/google-archive.gpg && \
  sh -c 'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list' && \
  apt-get update && \
  apt-get install google-chrome-stable -y --no-install-recommends && \
  rm -rf /var/lib/apt/lists/*

FROM common-test-image

ARG CONAN_REPO_URL=""
ARG VPN_LIBS_DIR=vpn-libs

WORKDIR /test/

COPY $VPN_LIBS_DIR /test/$VPN_LIBS_DIR

RUN conan remote add -i 0 art $CONAN_REPO_URL

WORKDIR /test/$VPN_LIBS_DIR/build
RUN cmake .. -DCMAKE_BUILD_TYPE=Release -G "Ninja" \
        -DCMAKE_C_COMPILER="clang" \
        -DCMAKE_CXX_COMPILER="clang++" \
        -DCMAKE_CXX_FLAGS="-stdlib=libc++" && \
    ninja standalone_client && \
    mv ./standalone_client/standalone_client /test/

WORKDIR /test/
COPY entrypoint.sh index.js package.json /test/
RUN npm install

ENTRYPOINT ["./entrypoint.sh"]
CMD ["endpoint_hostname", "endpoint_ip", "protocol", "mode", "socks_port"]
