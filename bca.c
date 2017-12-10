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
# define MAX_LABELS 44
mdl_u8_t *out = NULL;
mdl_u8_t *itr = NULL;

bci_addr_t get_off() {
	return itr-out;
}

typedef struct {
	char *name;
	bci_addr_t addr;
} label_t;

label_t **labels = NULL;
mdl_uint_t no_labels = 0;
bci_addr_t sp = 15;
# define RG_8A 0
# define RG_16A 1
# define RG_32A 3
# define RG_64A 7
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
	labels = (label_t**)malloc(MAX_LABELS*sizeof(label_t));
	itr = out;
}

mdl_u8_t size_to_bcit(mdl_u8_t __size) {
	switch(__size) {
		case 1:
			return _bcit_8l;
		case 2:
			return _bcit_16l;
		case 4:
			return _bcit_32l;
		case 8:
			return _bcit_64l;
	}
	return 0;
}

struct bca_blk {
	mdl_uint_t by;
	mdl_u8_t bcii, lt, rt, kind;
	bci_addr_t addr, dst_addr, src_addr;
	bci_addr_t l_addr, r_addr, cf_addr;
	mdl_u8_t exit_status;
	mdl_u64_t val;
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

void static make_nop(struct bca_blk *__blk, mdl_u8_t __flags) {
	*__blk = (struct bca_blk) {
		.bcii = _bcii_nop,
		.flags = __flags
	};
}

void static make_exit(struct bca_blk *__blk, mdl_u8_t __exit_status, mdl_u8_t __flags) {
	*__blk = (struct bca_blk) {
		.bcii = _bcii_exit,
		.exit_status = __exit_status,
		.flags = __flags
	};
}

void static make_as(struct bca_blk *__blk, bci_addr_t __addr, mdl_u64_t __val, mdl_u8_t __bcit, mdl_u8_t __flags) {
	*__blk = (struct bca_blk) {
		.bcii = _bcii_as,
		.addr = __addr,
		.val = __val,
		.bcit = __bcit,
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

void static make_aop(struct bca_blk *__blk, bci_addr_t __l_addr, bci_addr_t __r_addr, mdl_u8_t __kind, mdl_u8_t __bcit, mdl_u8_t __flags) {
	*__blk = (struct bca_blk) {
		.bcii = _bcii_aop,
		.l_addr = __l_addr,
		.r_addr = __r_addr,
		.kind = __kind,
		.bcit = __bcit,
		.flags = __flags
	};
}

void static make_incr_or_decr(struct bca_blk *__blk, mdl_u8_t __bcii, bci_addr_t __addr, mdl_uint_t __by, mdl_u8_t __flags) {
	*__blk = (struct bca_blk) {
		.bcii = __bcii,
		.addr = __addr,
		.by = __by,
		.flags = __flags
	};
}

void static make_cmp(struct bca_blk *__blk, bci_addr_t __l_addr, bci_addr_t __r_addr, mdl_u8_t __lt, mdl_u8_t __rt, bci_addr_t __cf_addr, mdl_u8_t __flags) {
	*__blk = (struct bca_blk) {
		.bcii = _bcii_cmp,
		.l_addr = __l_addr,
		.r_addr = __r_addr,
		.lt = __lt,
		.rt = __rt,
		.cf_addr = __cf_addr,
		.flags = __flags
	};
}

void static make_jmp(struct bca_blk *__blk, bci_addr_t __addr, mdl_u8_t __flags) {
	*__blk = (struct bca_blk) {
		.bcii = _bcii_jmp,
		.addr = __addr,
		.flags = __flags
	};
}

void static make_cjmp(struct bca_blk *__blk, bci_addr_t __addr, bci_addr_t __cf_addr) {

}

void static make_dr(struct bca_blk *__blk, bci_addr_t __addr) {

}

void static make_conv(struct bca_blk *__blk) {

}

void static make_extc(struct bca_blk *__blk) {


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

label_t* find_label(char *__name) {
	label_t **itr = labels;
	while(itr != labels+no_labels) {
		if (strcmp((*itr)->name, __name))
			return *itr;
		itr++;
	}
}

bci_addr_t get_reg(mdl_u8_t __bcit) {
	switch(__bcit) {
		case _bcit_8l: return RG_8A;
		case _bcit_16l: return RG_16A;
		case _bcit_32l: return RG_32A;
		case _bcit_64l: return RG_64A;
	}
	return 0;
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
	if ((*s >= 'a' && *s <= 'z') || *s == '_') {
		if (!strcmp(s, "_8l"))
			ret = _bcit_8l;
		else if (!strcmp(s, "_16l"))
			ret = _bcit_16l;
		else if (!strcmp(s, "_32l"))
			ret = _bcit_32l;
		else if (!strcmp(s, "_64l"))
			ret = _bcit_64l;
		else if (!strcmp(s, "sp"))
			ret = sp;
		else if (!strcmp(s, "rg_8a"))
			ret = RG_8A;
		else if (!strcmp(s, "rg_16a"))
			ret = RG_16A;
		else if (!strcmp(s, "rg_32a"))
			ret = RG_32A;
		else if (!strcmp(s, "rg_64a"))
			ret = RG_64A;
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

void emit_32l(mdl_u32_t __v) {
	emit_16l(__v);
	emit_16l(__v>>16);
}

void emit_64l(mdl_u64_t __v) {
	emit_32l(__v);
	emit_32l(__v>>32);
}

void emit(mdl_u8_t __bc, mdl_u8_t *__p) {
	mdl_u8_t *itr = __p;
	while(itr != __p+__bc) emit_8l(*(itr++));
}

void static emit_no(mdl_u64_t __no) {
	mdl_u8_t size = 0;
	mdl_u64_t no = __no;
	while (no != 0 && size != 8) {
		no = no>>8;
		size++;
	}

	if (size == 3)
		size = 4;
	else if (size > 4 && size < 8)
		size = 8;

	switch(size) {
		case 1:
			emit_8l(_bcit_8l);
			emit_8l(__no&0xFF);
		break;
		case 2:
			emit_8l(_bcit_16l);
			emit_16l(__no&0xFFFF);
		break;
		case 4:
			emit_8l(_bcit_32l);
			emit_32l(__no&0xFFFFFFFF);
		break;
		case 8:
			emit_8l(_bcit_64l);
			emit_64l(__no);
		break;
	}
}

void static emit_nop(mdl_u8_t __flags) {
	emit_8l(_bcii_nop);
	emit_8l(__flags);
}

void static emit_as(bci_addr_t __addr, mdl_u64_t __val, mdl_u8_t __bcit, mdl_u8_t __flags) {
	emit_8l(_bcii_as);
	emit_8l(__flags);
	emit_8l(__bcit);
	emit_16l(__addr);
	emit(bcit_sizeof(__bcit), (mdl_u8_t*)&__val);
}

void static emit_aop(bci_addr_t __l_addr, bci_addr_t __r_addr, bci_addr_t __dst_addr, mdl_u8_t __kind, mdl_u8_t __bcit, mdl_u8_t __flags) {
	emit_8l(_bcii_aop);
	emit_8l(__flags);
	emit_8l(__kind);
	emit_8l(__bcit);
	emit_16l(__dst_addr);
	emit_16l(__l_addr);
	emit_16l(__r_addr);
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

void static emit_jmp(bci_addr_t __addr, mdl_u8_t __flags) {
	emit_8l(_bcii_jmp);
	emit_8l(__flags);
	emit_16l(__addr);
}

void static gen(struct bca_blk *__blk) {
	struct bca_blk *blk = __blk;
	while(blk != NULL) {
		switch(blk->bcii) {
			case _bcii_nop:
				emit_nop(blk->flags);
			break;
			case _bcii_as:
				emit_as(blk->addr, blk->val, blk->bcit, blk->flags);
			break;
			case _bcii_aop:
				emit_aop(blk->l_addr, blk->r_addr, blk->dst_addr, blk->kind, blk->bcit, blk->flags);
			break;
			case _bcii_jmp: {
				emit_as(RG_16A, blk->addr, _bcit_16l, 0x0);
				emit_jmp(RG_16A, blk->flags);
				break;
			}
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

void static read_nop(char **__itr, struct bca_blk *__blk) {
	mdl_u8_t flags = read_literal(__itr);
	make_nop(__blk, flags);
}

void static read_as(char **__itr, struct bca_blk *__blk) {
	bci_addr_t addr = read_literal(__itr);
	mdl_u64_t val = read_literal(__itr);
	mdl_u8_t bcit = read_literal(__itr);
	mdl_u8_t flags = read_literal(__itr);
	make_as(__blk, addr, val, bcit, flags);
}

void static read_aop(char **__itr, struct bca_blk *__blk) {
	bci_addr_t l_addr = read_literal(__itr);
	bci_addr_t r_addr = read_literal(__itr);
	mdl_u8_t kind = read_literal(__itr);
	mdl_u8_t bcit = read_literal(__itr);
	mdl_u8_t flags = read_literal(__itr);
	make_aop(__blk, l_addr, r_addr, kind, bcit, flags);
}

void static read_jmp(char **__itr, struct bca_blk *__blk) {
	bci_addr_t addr;
	while(*itr == ' ') itr++;
	if ((*itr >= 'a' && *itr <= 'z') || *itr == '_') {
		mdl_uint_t l;
		char *name = extract(__itr, &l);
		label_t *label = find_label(name);
		if (label != NULL)
			addr = label->addr;
		else
			fprintf(stdout, "error can't find label.\n");
		free(name);
	} else
		addr = read_literal(__itr);

	mdl_u8_t flags = read_literal(__itr);
	make_jmp(__blk, addr, flags);
}

void bca_process() {
	char *f_itr = f;
	struct bca_blk *root = NULL;
	struct bca_blk *blk = NULL, *tail;
	while(f_itr < f+size && *f_itr != '\0') {
		tail = (struct bca_blk*)malloc(sizeof(struct bca_blk));
		tail->next = NULL;
		if (root == NULL)
			root = tail;

		if (blk != NULL)
			blk->next = tail;

		mdl_uint_t l;
		char *d;
		_back:
		d = extract(&f_itr, &l);
		if (d == NULL || !l) {
			blk->next = NULL;
			free(tail);
			goto _end;
		}

		if (*(d+l-1) == ':') {
			fprintf(stdout, "label added.\n");
			label_t *label = (*(labels+no_labels) = (label_t*)malloc(sizeof(label_t)));
			label->name = (char*)malloc(l+1);
			char *itr = d;
			while (*itr != ':')
				*(label->name+(itr-d)) = *(itr++);

			*itr = '\0';
			label->addr = get_off();
			goto _back;
		}

		if (!strcmp(d, "jmp"))
			read_jmp(&f_itr, tail);
		else if (!strcmp(d, "nop"))
			read_nop(&f_itr, tail);
		else if (!strcmp(d, "as"))
			read_as(&f_itr, tail);
		else if (!strcmp(d, "aop"))
			read_aop(&f_itr, tail);
		else if (!strcmp(d, "mov"))
			read_mov(&f_itr, tail);
		else if (!strcmp(d, "print"))
			read_print(&f_itr, tail);
		else if (!strcmp(d, "exit"))
			read_exit(&f_itr, tail);
		else {
			fprintf(stdout, "unkown %s\n", d);
		}

		if (d != NULL)
			free(d);
		blk = tail;
	}
	_end:
	gen(root);
}

void bca_save(char *__file) {
	int fd = open(__file, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
	write(fd, out, itr-out);
	close(fd);
}

void bca_clean() {
	free(labels);
	free(f);
	free(out);
}
