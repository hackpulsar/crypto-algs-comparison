#ifndef ERROR_HANDLER_H
#define ERROR_HANDLER_H

#include <iostream>
#include <vector>

void handleErrors() {
    std::cerr << "An error occurred!" << std::endl;
    exit(EXIT_FAILURE);
}

#endif //ERROR_HANDLER_H
