int common_value;
static int zero_values[16];
int data_value = 42;
const char const_message[] = "const";

const char *get_message(void) { return "cstring"; }

void set_value(int x, int value) { zero_values[x & 15] = value; }

int add(int x) { return x + data_value + zero_values[x & 15] + common_value; }
