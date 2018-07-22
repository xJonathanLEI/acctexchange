#include <eosiolib/eosio.hpp>
#include <eosiolib/asset.hpp>

#include <string>
#include <limits>

#include "base58.hpp"

using namespace std;
using namespace eosio;

struct transfer_args
{
    account_name from;
    account_name to;
    asset quantity;
    string memo;
};

struct assertowner_args
{
    account_name acct;
};

struct public_key_data
{
    uint8_t type;
    array<unsigned char, 33> data;
};

struct permission_level_weight
{
    permission_level permission;
    weight_type weight;
};

struct key_weight
{
    public_key_data key;
    weight_type weight;
};

struct authority
{
    uint32_t threshold;
    uint32_t delay_sec;
    vector<key_weight> keys;
    vector<permission_level_weight> accounts;
};

struct updateauth_args
{
    account_name account;
    permission_name permission;
    permission_name parent;
    authority data;
};

class acctexchange : public contract
{
  public:
    using contract::contract;

    const account_name ADMIN = N(xjonathanlei);

    acctexchange(account_name self) : contract(self), forsales(self, self) {}

    /// @abi table forsales
    struct forsale
    {
        account_name acct;
        extended_asset price;
        account_name recipient;

        auto primary_key() const { return acct; }
    };

    /// @abi table balances
    struct user_balance
    {
        account_name user;
        vector<extended_asset> balances;

        auto primary_key() const { return user; }
    };

    typedef multi_index<N(forsales), forsale> tbl_forsales;
    typedef multi_index<N(balances), user_balance> tbl_user_balances;

    /* Public interfaces */

    /// @abi action
    void listforsale(account_name acct, extended_asset price, account_name recipient);
    /// @abi action
    void delistacct(account_name acct);
    /// @abi action
    void buyacct(account_name buyer, account_name target, extended_asset price, string pub_key);
    /// @abi action
    void withdraw(account_name user, extended_asset quantity);

    /* Admin interfaces */

    /// @abi action
    void adjustfee(uint64_t new_fee);
    /// @abi action
    void removesale(account_name acct);

    /* Internal interfaces */

    /// @abi action
    void assertowner(account_name acct);

    void handle_transfer(account_name from, account_name to, extended_asset quantity, string memo);

  private:
    tbl_forsales forsales;

    void sub_balance(account_name user, extended_asset quantity);
};

extern "C"
{
    void apply(uint64_t receiver, uint64_t code, uint64_t action)
    {
        auto self = receiver;
        acctexchange thiscontract(self);
        if (code == self)
        {
            switch (action)
            {
                EOSIO_API(acctexchange, (listforsale)(delistacct)(buyacct)(withdraw)(adjustfee)(removesale)(assertowner))
            }
        }
        else
        {
            if (action == N(transfer))
            {
                auto transfer_data = unpack_action_data<transfer_args>();
                thiscontract.handle_transfer(transfer_data.from, transfer_data.to, extended_asset(transfer_data.quantity, code), transfer_data.memo);
            }
        }
    }
}
