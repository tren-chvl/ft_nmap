NAME =  ft_nmap
CC = cc
CFLAGS = -g -Wall -Wextra -Werror -I.

SRC = src/main.c \
		src/parse.c \
		src/scan.c \
		src/thread.c \
		src/scan/scan_syn.c \
		src/scan/scan_null.c \
		src/scan/generique.c \
		src/scan/scan_fin.c \
		src/scan/scan_xmas.c \
		src/scan/scan_ack.c \
		src/scan/scan_udp.c \
		src/bonus/DNS.c \
		src/bonus/detect_os.c

OBJ = $(SRC:.c=.o)

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -lpcap -pthread -o $(NAME)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re