Feature: XXXn-N paradigm
    Scenario: Decreasing hop count on WIDE
        Given the digicall is <digicall>
        And there is no message transmitted in the recently transmitted packets history
        When the packet <input> is received
        Then the packet is digipeated as <output>
        And the recently transmitted packets history contains the received packet <input> with timestamp

        Examples:
            | digicall | input                                         | output                                        |
            | "WW1ABC" | "WB2OSZ>XXXX,WIDE1-3:whatever"                | "WB2OSZ>XXXX,WW1ABC*,WIDE1-2:whatever"        |
            | "WW2DEF" | "WB2OSZ>XXXX,WW1ABC*,WIDE1-2:whatever"        | "WB2OSZ>XXXX,WW1ABC,WW2DEF*,WIDE1-1:whatever" |
            | "W3GHI"  | "WB2OSZ>XXXX,WW1ABC,WW2DEF*,WIDE1-1:whatever" | "WB2OSZ>XXXX,WW1ABC,WW2DEF,W3GHI*:whatever"   |

    Scenario: Decreasing hop on MA
        Given the digicall is "WW1ABC"
        And there is no message transmitted in the recently transmitted packets history
        And the list of authorised prefix contains "MA"
        When the packet "WB2OSZ>XXXX,MA1-3:whatever" is received
        Then the packet is digipeated as "WB2OSZ>XXXX,WW1ABC*,MA1-2:whatever" 
        And the recently transmitted packets history contains the received packet with timestamp
