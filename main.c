# include "bca.h"
int main(void) {
	bca_init("test.bca");
	bca_process();
	bca_save("a.out");
	bca_clean();
}
