Feature: Duplicate suppression
    Scenario: message suppressed
        Given the time limit for suppression is 30s
        And there is already a message with source "WB2OSZ", destination "XXXX", and payload "whatever" in the recently transmitted packets history
        When the packet "WB2OSZ>XXXX,MA1-3:whatever" is received
        Then the packet is rejected
        And the recently transmitted packets history is unchanged timestamp