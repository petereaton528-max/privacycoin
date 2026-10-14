// Phase 0 deterministic companion. Resolver results are synthetic test inputs.
// GNU linker wrapping applies to this executable ONLY, never node/wallet/unit_tests.
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include <unbound.h>
#include "common/dns_utils.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"

namespace {
std::vector<std::string> raw_records;
std::vector<std::string> queries;
int api_error = 0, result_rcode = 0;
bool result_secure = true, result_bogus = false;
unsigned checks = 0;
const std::string address = "46BeWrHpwXmHDpDEUmZBWZfoQpdc6HaERCNmx1pEYL2rAcuwufPN9rXHHtyUA4QVy66qeFQkn6sfK8aHYjA3jk3o1Bv16em";
void require(bool value, const char* name) {
  if (!value) throw std::runtime_error(name);
  ++checks;
}
std::string wire(const std::string& text) {
  if (text.size() > 255) throw std::runtime_error("fixture TXT string too long");
  return std::string(1, static_cast<char>(text.size())) + text;
}
std::string oa(const std::string& value) { return "oa1:xmr recipient_address=" + value + ";"; }
void fixture(std::vector<std::string> records, bool secure = true, bool bogus = false, int error = 0, int rcode = 0) {
  raw_records = std::move(records); result_secure = secure; result_bogus = bogus;
  api_error = error; result_rcode = rcode; queries.clear();
}
}

extern "C" int __wrap_ub_resolve(ub_ctx*, const char* name, int type, int klass, ub_result** output) {
  *output = nullptr;
  if (type != tools::DNS_TYPE_TXT || klass != tools::DNS_CLASS_IN) return UB_SYNTAX;
  const bool bootstrap = std::string(name) == "updates.moneropulse.org";
  if (!bootstrap && std::string(name) != "fixture.invalid") return UB_SYNTAX;
  queries.emplace_back(name);
  if (!bootstrap && api_error) return api_error;
  auto* result = new ub_result{};
  result->rcode = bootstrap ? 0 : result_rcode;
  result->secure = bootstrap || result_secure;
  result->bogus = !bootstrap && result_bogus;
  if (result->bogus) result->why_bogus = strdup("synthetic invalid-signature flag; no DNSSEC authentication performed");
  const size_t count = bootstrap ? 0 : raw_records.size();
  result->havedata = count != 0;
  result->data = new char*[count + 1]{};
  result->len = new int[count]{};
  for (size_t index = 0; index < count; ++index) {
    result->len[index] = static_cast<int>(raw_records[index].size());
    result->data[index] = new char[raw_records[index].size() + 1]{};
    std::memcpy(result->data[index], raw_records[index].data(), raw_records[index].size());
  }
  *output = result;
  return 0;
}
extern "C" void __wrap_ub_resolve_free(ub_result* result) {
  if (!result) return;
  for (size_t index = 0; result->data[index]; ++index) delete[] result->data[index];
  delete[] result->data; delete[] result->len;
  std::free(result->why_bogus); delete result;
}

int main() {
  try {
    // Construction probe is intercepted too. There is no DNS socket query.
    auto& resolver = tools::DNSResolver::instance();
    fixture({wire(oa(address))});
    bool available = false, valid = false;
    const auto records = resolver.get_txt_record("fixture.invalid", available, valid);
    require(records == std::vector<std::string>{oa(address)}, "real TXT reader decodes fixture RDATA");
    require(available && valid, "secure flag propagated, not authenticated by this mock");
    require(queries == std::vector<std::string>{"fixture.invalid"}, "query passed only to mock API");

    bool dnssec = false;
    fixture({wire(oa(address))});
    require(tools::dns_utils::addresses_from_url("fixture.invalid", dnssec) == std::vector<std::string>{address}, "valid OpenAlias result");
    require(dnssec, "URL secure flag");
    fixture({wire(oa(address))});
    require(tools::dns_utils::addresses_from_url("fixture@invalid", dnssec) == std::vector<std::string>{address}, "at-sign normalized by upstream");
    require(queries == std::vector<std::string>{"fixture.invalid"}, "normalization before resolver");

    cryptonote::address_parse_info info{};
    require(cryptonote::get_account_address_from_str(info, cryptonote::MAINNET, address), "actual address checksum accepted");
    crypto::hash8 payment_id{};
    const auto integrated = cryptonote::get_account_integrated_address_as_str(cryptonote::MAINNET, info.address, payment_id);
    fixture({wire(oa(integrated))});
    const auto integrated_result = tools::dns_utils::addresses_from_url("fixture.invalid", dnssec);
    require(integrated_result == std::vector<std::string>{integrated}, "integrated address extracted");
    require(cryptonote::get_account_address_from_str(info, cryptonote::MAINNET, integrated), "integrated checksum validated");

    std::string bad_checksum = address;
    bad_checksum.back() = bad_checksum.back() == '1' ? '2' : '1';
    require(tools::dns_utils::address_from_txt_record(oa(bad_checksum)) == bad_checksum, "TXT extraction checks format/length only, not checksum");
    require(!cryptonote::get_account_address_from_str(info, cryptonote::MAINNET, bad_checksum), "actual validator rejects bad checksum");
    require(!cryptonote::get_account_address_from_str(info, cryptonote::MAINNET, std::string(95, '!')), "actual validator rejects malformed Base58");

    fixture({wire("unrelated TXT"), wire("oa1:btc recipient_address=" + address + ";"),
             wire("oa1:xmr other_field=value;"), wire("oa1:xmr recipient_address=short;"),
             wire("oa1:xmr recipient_address=" + address), wire(oa(address + "1")), std::string{}});
    require(tools::dns_utils::addresses_from_url("fixture.invalid", dnssec).empty(), "invalid OA fields/length/terminator and zero-length RDATA discarded");
    fixture({wire("unrelated TXT"), wire(oa(address)), wire(oa(integrated))});
    require(tools::dns_utils::addresses_from_url("fixture.invalid", dnssec) == std::vector<std::string>{address, integrated}, "multiple valid records retained, unrelated record ignored");

    fixture({});
    require(tools::dns_utils::addresses_from_url("fixture.invalid", dnssec).empty(), "no TXT records gives no address");
    fixture({}, false, false, UB_SERVFAIL);
    dnssec = true;
    require(tools::dns_utils::addresses_from_url("fixture.invalid", dnssec).empty(), "resolver API failure gives no address");
    require(!dnssec, "resolver API failure clears secure status");
    fixture({}, false, false, 0, 2);
    require(tools::dns_utils::addresses_from_url("fixture.invalid", dnssec).empty(), "SERVFAIL empty result gives no address");
    fixture({wire(oa(address))}, false, false);
    require(tools::dns_utils::addresses_from_url("fixture.invalid", dnssec) == std::vector<std::string>{address} && !dnssec, "unsigned data remains explicitly unauthenticated");
    fixture({wire(oa(address))}, false, true);
    require(tools::dns_utils::addresses_from_url("fixture.invalid", dnssec) == std::vector<std::string>{address} && !dnssec, "bogus flag never reported as authenticated");
    std::cout << "PASS " << checks << " deterministic OpenAlias/TXT checks; mocked resolver only; no live DNS/DNSSEC authentication\n";
  } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << "\n"; return 1; }
}
