#include <cstdlib>
#include <iostream>

#include "indicator.hpp"

namespace {

void require(bool condition, const char* message)
{
    if (!condition) {
        std::cerr << message << '\n';
        std::exit(EXIT_FAILURE);
    }
}

void test_access_point_pulses_blue_every_two_seconds()
{
    fg::IndicatorScheduler indicator;
    indicator.set_provisioning({fg::ProvisioningIndication::AccessPoint, true});

    require(indicator.update(0) == fg::IndicatorColor::Blue, "AP pulse must start blue");
    require(indicator.update(200) == fg::IndicatorColor::Off, "AP pulse must end after 200 ms");
    require(indicator.update(1999) == fg::IndicatorColor::Off, "AP must stay dark between pulses");
    require(indicator.update(2000) == fg::IndicatorColor::Blue, "AP must pulse again after two seconds");
}

void test_connecting_overrides_access_point_pulse()
{
    fg::IndicatorScheduler indicator;
    indicator.set_provisioning({fg::ProvisioningIndication::AccessPoint, true});
    indicator.update(0);
    indicator.set_provisioning({fg::ProvisioningIndication::Connecting, true});

    require(indicator.update(1) == fg::IndicatorColor::Yellow, "connecting must override the AP pulse");
}

void test_connection_success_flashes_three_times_then_returns_to_idle()
{
    fg::IndicatorScheduler indicator;
    indicator.set_provisioning({fg::ProvisioningIndication::Connecting, true});
    require(indicator.update(0) == fg::IndicatorColor::Yellow, "connecting must be yellow");
    indicator.set_provisioning({fg::ProvisioningIndication::Connected, true});

    require(indicator.update(1) == fg::IndicatorColor::Green, "success must begin green");
    require(indicator.update(201) == fg::IndicatorColor::Off, "success flash must turn off");
    require(indicator.update(401) == fg::IndicatorColor::Green, "success must flash a second time");
    require(indicator.update(801) == fg::IndicatorColor::Green, "success must flash a third time");
    require(indicator.update(1201) == fg::IndicatorColor::Blue, "success must return to idle blue");
    require(indicator.update(1401) == fg::IndicatorColor::Blue, "connected station must not resume AP pulses while waiting for acknowledgement");
    require(indicator.update(3201) == fg::IndicatorColor::Blue, "connected station must remain steady blue");
}

void test_connection_failure_flashes_three_times_then_returns_to_idle()
{
    fg::IndicatorScheduler indicator;
    indicator.set_provisioning({fg::ProvisioningIndication::Connecting, false});
    indicator.update(0);
    indicator.set_provisioning({fg::ProvisioningIndication::Failed, false});

    require(indicator.update(1) == fg::IndicatorColor::Red, "failure must begin red");
    require(indicator.update(401) == fg::IndicatorColor::Red, "failure must flash a second time");
    require(indicator.update(801) == fg::IndicatorColor::Red, "failure must flash a third time");
    require(indicator.update(1201) == fg::IndicatorColor::Blue, "failure without AP must return to idle blue");
}

}

int main()
{
    fg::IndicatorScheduler enrollment;
    enrollment.set_provisioning({fg::ProvisioningIndication::Connected, false});
    enrollment.update(0);
    enrollment.set_enrollment(true);
    require(enrollment.update(1) == fg::IndicatorColor::Yellow, "enrollment overrides connection flashes");
    require(enrollment.update(2000) == fg::IndicatorColor::Yellow, "enrollment stays yellow without blocking scans");
    enrollment.set_enrollment(false);
    enrollment.show_result(true, 2001);
    require(enrollment.update(2001) == fg::IndicatorColor::Green, "successful enrollment starts green flashes");
    require(enrollment.update(3201) == fg::IndicatorColor::Blue, "successful enrollment returns to idle");
    test_access_point_pulses_blue_every_two_seconds();
    test_connecting_overrides_access_point_pulse();
    test_connection_success_flashes_three_times_then_returns_to_idle();
    test_connection_failure_flashes_three_times_then_returns_to_idle();
    return EXIT_SUCCESS;
}
