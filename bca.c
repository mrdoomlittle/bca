# include "bca.h"
# include <malloc.h>
# include <sys/stat.h>
# include <fcntl.h>
# include <unistd.h>
# include <stdio.h>
# include <string.h>
# include <mdl/bci.h>
char *f;
mdl_uint_t size;

mdl_u8_t *out = NULL;
mdl_u8_t *itr = NULL;
void bca_init(char *__file) {
	int fd;
	if ((fd = open(__file, O_RDONLY)) == -1) {
		fprintf(stderr, "failed to open src file.\n");
		return;
	}

	struct stat st;
	stat(__file, &st);
	f = (char*)malloc(size = st.st_size);
	read(fd, f, st.st_size);
	close(fd);

	out = (mdl_u8_t*)malloc(800);
	itr = out;
}

struct bca_blk {
	mdl_u8_t bcii;
	bci_addr_t addr, dst_addr, src_addr;
	mdl_u8_t exit_status;
	mdl_u8_t bcit, flags;
	struct bca_blk *next;
};

mdl_u8_t ignore_space(char __c) {
	if (__c == ' ' || __c == '\n') return 1;
	return 0;
}

mdl_uint_t partl(char *__s) {
	char *itr = __s;
	while(*itr != ' ' && *itr != '\n' && *itr != '\0') itr++;
	return itr-__s;
}

char static* extract(char **__itr, mdl_uint_t *__l) {
	while(ignore_space(**__itr)) (*__itr)++;
	*__l = partl(*__itr);
	if ((*__l) == 0) return NULL;
	char *s = (char*)malloc((*__l)+1);
	char *itr = s, *end = s+(*__l);
	while(itr != end)
		*(itr++) = *((*__itr)++);
	*itr = '\0';
	return s;
}

void static make_exit(struct bca_blk *__blk, mdl_u8_t __exit_status, mdl_u8_t __flags) {
	*__blk = (struct bca_blk) {
		.bcii = _bcii_exit,
		.exit_status = __exit_status,
		.flags = __flags
	};
}

void static make_mov(struct bca_blk *__blk, bci_addr_t __dst_addr, bci_addr_t __src_addr, mdl_u8_t __bcit, mdl_u8_t __flags) {
	*__blk = (struct bca_blk) {
		.bcii = _bcii_mov,
		.dst_addr = __dst_addr,
		.src_addr = __src_addr,
		.bcit = __bcit,
		.flags = __flags
	};
}

void static make_print(struct bca_blk *__blk, bci_addr_t __addr, mdl_u8_t __bcit, mdl_u8_t __flags) {
	*__blk = (struct bca_blk) {
		.bcii = _bcii_print,
		.addr = __addr,
		.bcit = __bcit,
		.flags = __flags
	};
}

mdl_uint_t hex_to_int(char *__hex) {
	char *itr = __hex;
	mdl_uint_t l = strlen(__hex);
	char c;
	mdl_uint_t val = 0;
	while(itr++ != __hex+l) {
		c = *(itr-1);
		if (c >= '0' && c <= '9')
			val = (val<<4)|((c-'0')&0xF);
		else if (c >= 'A' && c <= 'F')
			val = (val<<4)|(((c-'A')+10)&0xF);
	}
	return val;
}

mdl_uint_t str_to_int(char *__str) {
	mdl_uint_t no_unit = 1, no = 0;
	for (mdl_uint_t ic = 0;; ic++) {
		if (__str[ic+1] == '\0') break;
		no_unit = no_unit*10;
	}

	for (mdl_u8_t *itr = __str;; itr++) {
		if (*itr == '\0') break;
		switch(*itr) {
			case '0': break;
			case '1': no += 1*no_unit; break;
			case '2': no += 2*no_unit; break;
			case '3': no += 3*no_unit; break;
			case '4': no += 4*no_unit; break;
			case '5': no += 5*no_unit; break;
			case '6': no += 6*no_unit; break;
			case '7': no += 7*no_unit; break;
			case '8': no += 8*no_unit; break;
			case '9': no += 9*no_unit; break;
			default: return 0;
		}

		if (no_unit != 1) no_unit = no_unit/10;
	}
	return no;
}

mdl_u64_t read_literal(char **__itr) {
	mdl_uint_t ret = 0;
	mdl_uint_t l;
	char *s = extract(__itr, &l);
	if (s == NULL) return l;
	if (*s >= '0' && *s <= '9')
		ret = str_to_int(s);

	if (l > 2) {
		if (*s == '0' && *(s+1) == 'x')
			ret = hex_to_int(s);
	}

	if (*s >= 'a' && *s <= 'z') {
		if (!strcmp(s, "bcit_8l"))
			ret = _bcit_8l;
		else if (!strcmp(s, "bcit_16l"))
			ret = _bcit_16l;
		else if (!strcmp(s, "bcit_32l"))
			ret = _bcit_32l;
		else if (!strcmp(s, "bcit_64l"))
			ret = _bcit_64l;
	}
	free(s);
	return ret;
}

void emit_8l(mdl_u8_t __v) {
	*(itr++) = __v;
}

void emit_16l(mdl_u16_t __v) {
	emit_8l(__v);
	emit_8l(__v>>8);
}

void static emit_mov(bci_addr_t __dst_addr, bci_addr_t __src_addr, mdl_u8_t __bcit, mdl_u8_t __flags) {
	emit_8l(_bcii_mov);
	emit_8l(__flags);
	emit_8l(__bcit);
	emit_16l(__dst_addr);
	emit_16l(__src_addr);
}

void static emit_print(bci_addr_t __addr, mdl_u8_t __bcit, mdl_u8_t __flags) {
	emit_8l(_bcii_print);
	emit_8l(__flags);
	emit_8l(__bcit);
	emit_16l(__addr);
}

void static emit_exit(mdl_u8_t __exit_status, mdl_u8_t __flags) {
	emit_8l(_bcii_exit);
	emit_8l(__flags);
	emit_8l(__exit_status);
}

void static gen(struct bca_blk *__blk) {
	struct bca_blk *blk = __blk;
	while(blk != NULL) {
		switch(blk->bcii) {
			case _bcii_mov:
				emit_mov(blk->dst_addr, blk->src_addr, blk->bcit, blk->flags);
			break;
			case _bcii_print:
				emit_print(blk->addr, blk->bcit, blk->flags);
			break;
			case _bcii_exit:
				emit_exit(blk->exit_status, blk->flags);
			break;
		}
		blk = blk->next;
	}
}

void static read_mov(char **__itr, struct bca_blk *__blk) {
	bci_addr_t dst_addr = read_literal(__itr);
	bci_addr_t src_addr = read_literal(__itr);
	mdl_u8_t bcit = read_literal(__itr);
	mdl_u8_t flags = read_literal(__itr);
	make_mov(__blk, dst_addr, src_addr, bcit, flags);
}

void static read_exit(char **__itr, struct bca_blk *__blk) {
	mdl_u8_t exit_status = read_literal(__itr);
	mdl_u8_t flags = read_literal(__itr);
	make_exit(__blk, exit_status, flags);
}

void static read_print(char **__itr, struct bca_blk *__blk) {
	bci_addr_t addr = read_literal(__itr);
	mdl_u8_t bcit = read_literal(__itr);
	mdl_u8_t flags = read_literal(__itr);
	make_print(__blk, addr, bcit, flags);
}

void bca_process() {
	char *f_itr = f;
	struct bca_blk *begin = NULL;
	struct bca_blk *blk = NULL, *tail;
	while(f_itr < f+size-2) {
		tail = (struct bca_blk*)malloc(sizeof(struct bca_blk));
		tail->next = NULL;
		if (begin == NULL)
			begin = tail;

		if (blk != NULL)
			blk->next = tail;

		mdl_uint_t l;
		char *d = extract(&f_itr, &l);
		if (!strcmp(d, "mov"))
			read_mov(&f_itr, tail);
		else if (!strcmp(d, "print"))
			read_print(&f_itr, tail);
		else if (!strcmp(d, "exit"))
			read_exit(&f_itr, tail);
		if (d != NULL)
			free(d);
		blk = tail;
	}
	gen(begin);
}

void bca_save(char *__file) {
	int fd = open(__file, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
	write(fd, out, itr-out);
	close(fd);
}

void bca_clean() {
	free(f);
	free(out);
}
