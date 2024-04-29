#include <iostream>
#include <fstream>
extern "C" int Transform(const char *str)
{
    printf("aop_transform_start");
    printf("%s", str);
    std::ofstream file(str, std::ios::out | std::ios::trunc);
    file << "new_abc_content";
    file.close();
    return 0;
}