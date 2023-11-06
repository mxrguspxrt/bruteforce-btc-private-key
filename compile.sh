rm ./btc_address
g++ -o btc_address btc_address.cpp -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lcrypto -std=c++17

