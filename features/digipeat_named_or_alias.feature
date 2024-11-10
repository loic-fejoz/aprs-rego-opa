Feature: Named or alias digipeating

    Scenario: Digipeater callsign is next unused
        Given the digicall is "N2GH"
        And there is no message transmitted in the recently transmitted packets history
        When the packet "WB2OSZ>APRS,N2GH,W2UB:something" is received
        Then the packet is digipeated as "WB2OSZ>APRS,N2GH*,W2UB:something"
        And the recently transmitted packets history contains the received packet with timestamp

        Given the digicall is "W2UB"
        And there is no message transmitted in the recently transmitted packets history
        When the packet "WB2OSZ>APRS,N2GH*,W2UB:something" is received
        Then the packet is digipeated as "WB2OSZ>APRS,N2GH,W2UB*:something"
        And the recently transmitted packets history contains the received packet with timestamp

    Scenario: One alias of the digipeater is next unused
        Given the digicall is "KB1MKZ"
        And digipeater's aliases contains "EOC"
        And there is no message transmitted in the recently transmitted packets history
        When the packet "WB2OSZ>APRS,EOC:something" is received
        Then the packet is digipeated as "WB2OSZ>APRS,KB1MKZ*:something"
        And the recently transmitted packets history contains the received packet with timestamp
