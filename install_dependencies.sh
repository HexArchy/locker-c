#!/bin/bash

# Update package list
sudo apt-get update

# Install build essentials (includes gcc and make)
sudo apt-get install -y build-essential

# Install libcrypt-dev for crypt function
sudo apt-get install -y libcrypt-dev

echo "Dependencies installed successfully."