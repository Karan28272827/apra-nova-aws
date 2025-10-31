# ===========================================================
# 🧠 Base Image: Official Code-Server
# ===========================================================
FROM codercom/code-server:latest

# ===========================================================
# 🧰 System Setup & Language Installations
# ===========================================================
USER root

RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    wget \
    git \
    unzip \
    software-properties-common \
    && rm -rf /var/lib/apt/lists/*

# ===========================================================
# 🐍 Python Installation
# ===========================================================
RUN apt-get update && apt-get install -y python3 python3-pip python3-venv && \
    rm -rf /var/lib/apt/lists/*

# Install common Python packages (⚡ fixed for PEP 668)
RUN pip3 install --no-cache-dir --break-system-packages \
    numpy pandas requests flask matplotlib jupyter black pylint pytest

RUN ln -s /usr/bin/python3 /usr/bin/python

# ===========================================================
# 🟢 Node.js Installation (LTS)
# ===========================================================
RUN curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - && \
    apt-get install -y nodejs && \
    npm install -g yarn pm2 typescript ts-node

# ===========================================================
# ☕ Java Installation
# ===========================================================
RUN apt-get update && apt-get install -y openjdk-17-jdk && \
    rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

# ===========================================================
# 💻 C/C++ (GCC & G++)
# ===========================================================
RUN apt-get update && apt-get install -y gcc g++ make cmake gdb && \
    rm -rf /var/lib/apt/lists/*

# ===========================================================
# 🧩 Developer Tools (Optional)
# ===========================================================
# RUN apt-get install -y vim nano && rm -rf /var/lib/apt/lists/*
RUN apt-get update && apt-get install -y vim-tiny nano && rm -rf /var/lib/apt/lists/*


# ===========================================================
# 👤 Security & Environment Setup
# ===========================================================
USER coder
WORKDIR /home/coder/project
EXPOSE 8080

ENV SHELL=/bin/bash
ENV LANG=C.UTF-8
