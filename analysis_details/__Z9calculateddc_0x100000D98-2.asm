; 函数: __Z9calculateddc
; 范围: 0x100000D98 - 0x100000EA4
; 大小: 268 字节
; ; 调用者: _main (0x100000F10), _main (0x100000F34)

0x100000D98    SUB             SP, SP, #0x50
0x100000D9C    STP             X29, X30, [SP,#0x40+var_s0]
0x100000DA0    ADD             X29, SP, #0x40
0x100000DA4    STUR            D0, [X29,#var_10]
0x100000DA8    STUR            D1, [X29,#var_18]
0x100000DAC    STURB           W0, [X29,#var_19]
0x100000DB0    LDUR            D1, [X29,#var_10]
0x100000DB4    LDUR            D0, [X29,#var_18]
0x100000DB8    LDURSB          W10, [X29,#var_19]
0x100000DBC    MOV             X9, SP
0x100000DC0    STR             D1, [X9,#0x40+var_40]
0x100000DC4    STR             D0, [X9,#0x40+var_38]
0x100000DC8    MOV             X8, X10
0x100000DCC    STR             X8, [X9,#0x40+var_30]
0x100000DD0    ADRL            X0, aCalculateALfBL; "[calculate] a=%lf,b=%lf,op=%c\n"
0x100000DD8    BL              _printf
0x100000DDC    LDURSB          W8, [X29,#var_19]
0x100000DE0    SUBS            W8, W8, #0x2B ; '+'
0x100000DE4    B.NE            loc_100000E00
0x100000DE8    B               loc_100000DEC
0x100000DEC    LDUR            D0, [X29,#var_10]
0x100000DF0    LDUR            D1, [X29,#var_18]
0x100000DF4    FADD            D0, D0, D1
0x100000DF8    STUR            D0, [X29,#var_8]
0x100000DFC    B               loc_100000E94
0x100000E00    LDURSB          W8, [X29,#var_19]
0x100000E04    SUBS            W8, W8, #0x2D ; '-'
0x100000E08    B.NE            loc_100000E24
0x100000E0C    B               loc_100000E10
0x100000E10    LDUR            D0, [X29,#var_10]
0x100000E14    LDUR            D1, [X29,#var_18]
0x100000E18    FSUB            D0, D0, D1
0x100000E1C    STUR            D0, [X29,#var_8]
0x100000E20    B               loc_100000E94
0x100000E24    LDURSB          W8, [X29,#var_19]
0x100000E28    SUBS            W8, W8, #0x2A ; '*'
0x100000E2C    B.NE            loc_100000E48
0x100000E30    B               loc_100000E34
0x100000E34    LDUR            D0, [X29,#var_10]
0x100000E38    LDUR            D1, [X29,#var_18]
0x100000E3C    FMUL            D0, D0, D1
0x100000E40    STUR            D0, [X29,#var_8]
0x100000E44    B               loc_100000E94
0x100000E48    LDURSB          W8, [X29,#var_19]
0x100000E4C    SUBS            W8, W8, #0x2F ; '/'
0x100000E50    B.NE            loc_100000E88
0x100000E54    B               loc_100000E58
0x100000E58    LDUR            D0, [X29,#var_18]
0x100000E5C    FCMP            D0, #0.0
0x100000E60    B.EQ            loc_100000E7C
0x100000E64    B               loc_100000E68
0x100000E68    LDUR            D0, [X29,#var_10]
0x100000E6C    LDUR            D1, [X29,#var_18]
0x100000E70    FDIV            D0, D0, D1
0x100000E74    STUR            D0, [X29,#var_8]
0x100000E78    B               loc_100000E94
0x100000E7C    FMOV            D0, #-1.0
0x100000E80    STUR            D0, [X29,#var_8]
0x100000E84    B               loc_100000E94
0x100000E88    FMOV            D0, #-1.0
0x100000E8C    STUR            D0, [X29,#var_8]
0x100000E90    B               loc_100000E94
0x100000E94    LDUR            D0, [X29,#var_8]
0x100000E98    LDP             X29, X30, [SP,#0x40+var_s0]
0x100000E9C    ADD             SP, SP, #0x50 ; 'P'
0x100000EA0    RET
