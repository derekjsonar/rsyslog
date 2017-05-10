// compile with
// g++ -std=c++11 -L/usr/lib64 -lboost_regex -o test_stream test_stream.cpp
#include <iostream>
#include <sstream>
#include <vector>
#include <array>
#include <boost/regex.hpp>
#include <boost/algorithm/string/regex.hpp>

using namespace std;
using namespace boost;

int main()
{
    std::string input_line;
    std::string working_line;
    vector<string> splitFields;

    while (getline(cin, input_line)) {
        split_regex(splitFields, input_line, regex("QWE"));
        if (!splitFields.empty()) {
            working_line += splitFields[0];
        }
        for (size_t i = 1; i < splitFields.size(); ++i) {
            cout << "-->" << working_line << endl;
            working_line.clear();
            working_line += splitFields[i];
        }
    }

    return 0;
}