#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include <vector>
//g++ test_von_neumann_extractor.cpp -o test_runner -std=c++17 -I"C:\Users\Tristan Ruel\vcpkg\installed\x64-windows\include"



std::vector<int> vonNeumannExtract(const std::vector<int>& input) {
    std::vector<int> output;
    for (size_t i = 0; i + 1 < input.size(); i += 2) {
        if (input[i] != input[i + 1]) {
            output.push_back(input[i]);
        }
    }
    return output;
}

TEST_CASE("Von Neumann extraction yields correct unbiased bits", "[vonNeumann]") {
    // (0,0) -> ignored, (0,1) -> yields 0, (1,0) -> yields 1,
    // (1,1) -> ignored, (1,0) -> yields 1.
    std::vector<int> input = {0, 0, 0, 1, 1, 0, 1, 1, 1, 0};
    std::vector<int> expected = {0, 1, 1};
    
    auto result = vonNeumannExtract(input);
    REQUIRE(result == expected);
}