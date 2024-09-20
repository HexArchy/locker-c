CC = gcc
CFLAGS = -Wall -Wextra -pedantic -std=c11 -I./include -D_GNU_SOURCE
LDFLAGS = -lcrypt

SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin
INSTALL_DIR = /bin

SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
TARGET = file_protection

.PHONY: all clean install run mkdir

all: install mkdir $(BIN_DIR)/$(TARGET) copy run

$(BIN_DIR)/$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

mkdir:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR)

install:
	@echo "Installing dependencies..."
	@sudo chmod +x ./install_dependencies.sh
	@sudo ./install_dependencies.sh

copy:
	@echo "Copying executable to $(INSTALL_DIR)..."
	@sudo mkdir -p $(INSTALL_DIR)
	@sudo cp $(BIN_DIR)/$(TARGET) $(INSTALL_DIR)/$(TARGET)

run:
	@clear
	@echo "Running $(TARGET)..."
	@sudo $(INSTALL_DIR)/$(TARGET)

clean:
	@rm -rf $(OBJ_DIR) $(BIN_DIR)
	@sudo rm -f $(INSTALL_DIR)/$(TARGET)