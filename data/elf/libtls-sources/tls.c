__thread unsigned int tdata_var = 0x11223344;
__thread unsigned long long tdata_var2 = 0x5566778899AABBCCull;
__thread char tbss_var[24];
unsigned int get(void) { return tdata_var + (unsigned int)tdata_var2 + (unsigned int)tbss_var[1]; }
