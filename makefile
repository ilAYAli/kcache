# (!c) petter wahlman
#
CC      = gcc

SRCDIR  = ./src
OBJDIR  = ./obj
BINDIR  = ./bin
INCLUDE = ./include

BINARY  = $(BINDIR)/kcache

CFLAGS  = -I $(INCLUDE) -g -Wall
LDFLAGS = -lcrypto

VPATH   = $(SRCDIR)

BINARY_OBJ = \
	$(OBJDIR)/kcache.o \
	$(OBJDIR)/crypto.o \
	$(OBJDIR)/util.o \
	$(OBJDIR)/lzss.o

$(OBJDIR)/%.o: %.c
	$(CC) -c $< $(CFLAGS) -o $@

.PHONY:
all:    make_dirs $(BINARY) install

$(BINARY): $(BINARY_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS) 

.PHONY:
clean:
	@rm -rvf \
		$(BINARY) \
		$(BINARY_OBJ)
	@-ls ./kcache/*kernelcache.* |grep -v release | xargs rm -v

.PHONY:
make_dirs:
	@mkdir -p $(OBJDIR) $(BINDIR)

.PHONY:
install:
	@if [ -d ~/bin ]; then \
		install $(BINARY) ~/bin; \
	else \
		sudo install $(BINARY) /usr/local/bin; \
	fi 

