#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ftu_inc.h"
#include "inc.h"

void register_module()
{
    tu_register_module(test_deal_duplicate, "for testing duplicate pkg");
    tu_register_module(test_deal_muddled,   "for testing muddled pkg");
}

int main(int argc, char** argv)
{
    tu_register_init();
    register_module();
    tu_run_cases();

    return 0;
}
