// compile with
// g++ -std=c++11 -L/usr/lib64 -lboost_regex -o test_stream test_stream.cpp
#include <iostream>
#include <vector>
#include <boost/algorithm/string/regex.hpp>

using namespace std;
using namespace boost;

int main()
{
    string inputLine;
    string workingLine;
    vector<string> splitFields;

    while (getline(cin, inputLine)) {
        split_regex(splitFields, inputLine, regex("QWE"));
        if (!splitFields.empty()) {
            workingLine += splitFields[0];
        }
        for (size_t i = 1; i < splitFields.size(); ++i) {
            cout << "-->" << workingLine << endl;
            workingLine.clear();
            workingLine += splitFields[i];
        }
    }

    return 0;
}