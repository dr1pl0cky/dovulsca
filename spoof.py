import sys, os

from colorama import init as color_init

import emailprotectionslib.dmarc as dmarclib
import emailprotectionslib.spf as spflib
import logging




logging.basicConfig(level=logging.INFO)


def check_spf_redirect_mechanisms(spf_record):
    redirect_domain = spf_record.get_redirect_domain()

    if redirect_domain is not None:
        print("Processing an SPF redirect domain: %s" % redirect_domain)

        return is_spf_record_strong(redirect_domain)

    else:
        return False


def check_spf_include_mechanisms(spf_record):
    include_domain_list = spf_record.get_include_domains()

    for include_domain in include_domain_list:
        print("Processing an SPF include domain: %s" % include_domain)

        strong_all_string = is_spf_record_strong(include_domain)

        if strong_all_string:
            return True

    return False


def is_spf_redirect_record_strong(spf_record):
    print("Checking SPF redirect domian: %(domain)s" % {"domain": spf_record.get_redirect_domain})
    redirect_strong = spf_record._is_redirect_mechanism_strong()
    if redirect_strong:
        print("Redirect mechanism is strong.")
    else:
        print("Redirect mechanism is not strong.")

    return redirect_strong


def are_spf_include_mechanisms_strong(spf_record):
    print("Checking SPF include mechanisms")
    include_strong = spf_record._are_include_mechanisms_strong()
    if include_strong:
        print("Include mechanisms include a strong record")
    else:
        print("Include mechanisms are not strong")

    return include_strong


def check_spf_include_redirect(spf_record):
    other_records_strong = False
    if spf_record.get_redirect_domain() is not None:
        other_records_strong = is_spf_redirect_record_strong(spf_record)

    if not other_records_strong:
        other_records_strong = are_spf_include_mechanisms_strong(spf_record)

    return other_records_strong


def check_spf_all_string(spf_record):
    strong_spf_all_string = True
    if spf_record.all_string is not None:
        if spf_record.all_string == "~all" or spf_record.all_string == "-all":
            print("SPF record contains an All item: " + spf_record.all_string)
        else:
            print("SPF record All item is too weak: " + spf_record.all_string)
            strong_spf_all_string = False
    else:
        print("SPF record has no All string")
        strong_spf_all_string = False

    if not strong_spf_all_string:
        strong_spf_all_string = check_spf_include_redirect(spf_record)

    return strong_spf_all_string


def is_spf_record_strong(domain):
    strong_spf_record = True
    spf_record = spflib.SpfRecord.from_domain(domain)
    if spf_record is not None and spf_record.record is not None:
        print("Found SPF record:")
        print(str(spf_record.record))

        strong_all_string = check_spf_all_string(spf_record)
        if strong_all_string is False:

            redirect_strength = check_spf_redirect_mechanisms(spf_record)
            include_strength = check_spf_include_mechanisms(spf_record)

            strong_spf_record = False

            if redirect_strength is True:
                strong_spf_record = True

            if include_strength is True:
                strong_spf_record = True
    else:
        print(domain + " has no SPF record!")
        strong_spf_record = False

    return strong_spf_record


def get_dmarc_record(domain):
    dmarc = dmarclib.DmarcRecord.from_domain(domain)
    if dmarc is not None and dmarc.record is not None:
        print("Found DMARC record:")
        print(str(dmarc.record))
    return dmarc


def get_dmarc_org_record(base_record):
    org_record = base_record.get_org_record()
    if org_record is not None:
        print("Found DMARC Organizational record:")
        print(org_record.record)
    return org_record


def check_dmarc_extras(dmarc_record):
    if dmarc_record.pct is not None and dmarc_record.pct != str(100):
        print("DMARC pct is set to " + dmarc_record.pct + "% - might be possible")

    if dmarc_record.rua is not None:
        print("Aggregate reports will be sent: " + dmarc_record.rua)

    if dmarc_record.ruf is not None:
        print("Forensics reports will be sent: " + dmarc_record.ruf)


def check_dmarc_policy(dmarc_record):
    policy_strength = False
    if dmarc_record.policy is not None:
        if dmarc_record.policy == "reject" or dmarc_record.policy == "quarantine":
            policy_strength = True
            print("DMARC policy set to " + dmarc_record.policy)
        else:
            print("DMARC policy set to " + dmarc_record.policy)
    else:
        print("DMARC record has no Policy")

    return policy_strength


def check_dmarc_org_policy(base_record):
    policy_strong = False

    try:
        org_record = base_record.get_org_record()
        if org_record is not None and org_record.record is not None:
            print("Found organizational DMARC record:")
            print(str(org_record.record))

            if org_record.subdomain_policy is not None:
                if org_record.subdomain_policy == "none":
                    print("Organizational subdomain policy set to %(sp)s" % {"sp": org_record.subdomain_policy})
                elif org_record.subdomain_policy == "quarantine" or org_record.subdomain_policy == "reject":
                    print("Organizational subdomain policy explicitly set to %(sp)s" % {"sp": org_record.subdomain_policy})
                    policy_strong = True
            else:
                print("No explicit organizational subdomain policy. Defaulting to organizational policy")
                policy_strong = check_dmarc_policy(org_record)
        else:
            print("No organizational DMARC record")

    except dmarclib.OrgDomainException:
        print("No organizational DMARC record")

    except Exception as e:
        logging.exception(e)

    return policy_strong


def is_dmarc_record_strong(domain):
    dmarc_record_strong = False

    dmarc = get_dmarc_record(domain)

    if dmarc is not None and dmarc.record is not None:
        dmarc_record_strong = check_dmarc_policy(dmarc)

        check_dmarc_extras(dmarc)
    elif dmarc.get_org_domain() is not None:
        print("No DMARC record found. Looking for organizational record")
        dmarc_record_strong = check_dmarc_org_policy(dmarc)
    else:
        print(domain + " has no DMARC record!")

    return dmarc_record_strong

if __name__ == "__main__":
    color_init()
    spoofable = False

    try:
        domain = sys.argv[1]

        spf_record_strength = is_spf_record_strong(domain)

        dmarc_record_strength = is_dmarc_record_strong(domain)
        if dmarc_record_strength is False:
            spoofable = True
        else:
            spoofable = False

        if spoofable:
            print("Spoofing possible for " + domain + "!")
        else:
            print("Spoofing not possible for " + domain)

    except IndexError:
        print("Usage: " + sys.argv[0] + " [DOMAIN]")
