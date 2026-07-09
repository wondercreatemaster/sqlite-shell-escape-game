# Terminus Forge — Policy Dossier (change log)
# Each directive: REV <id> | param=<name> | value=<val> | supersedes=<REV|none> | status=<active|revoked>

REV 1001 | param=threshold_0 | value=0 | supersedes=none | status=active   # initial
REV 1002 | param=threshold_0 | value=0 | supersedes=1001 | status=active   # revised
REV 1003 | param=threshold_0 | value=999 | supersedes=1002 | status=revoked   # rolled back
REV 1004 | param=threshold_1 | value=1 | supersedes=none | status=active   # initial
REV 1005 | param=threshold_1 | value=2 | supersedes=1004 | status=active   # revised
REV 1006 | param=threshold_2 | value=2 | supersedes=none | status=active   # initial
REV 1007 | param=threshold_2 | value=4 | supersedes=1006 | status=active   # revised
REV 1008 | param=threshold_3 | value=3 | supersedes=none | status=active   # initial
REV 1009 | param=threshold_3 | value=6 | supersedes=1008 | status=active   # revised
REV 1010 | param=threshold_3 | value=999 | supersedes=1009 | status=revoked   # rolled back
REV 1011 | param=threshold_4 | value=4 | supersedes=none | status=active   # initial
REV 1012 | param=threshold_4 | value=8 | supersedes=1011 | status=active   # revised
REV 1013 | param=threshold_5 | value=5 | supersedes=none | status=active   # initial
REV 1014 | param=threshold_5 | value=10 | supersedes=1013 | status=active   # revised
REV 1015 | param=threshold_6 | value=6 | supersedes=none | status=active   # initial
REV 1016 | param=threshold_6 | value=12 | supersedes=1015 | status=active   # revised
REV 1017 | param=threshold_6 | value=999 | supersedes=1016 | status=revoked   # rolled back
REV 1018 | param=threshold_7 | value=7 | supersedes=none | status=active   # initial
REV 1019 | param=threshold_7 | value=14 | supersedes=1018 | status=active   # revised
REV 1020 | param=threshold_8 | value=8 | supersedes=none | status=active   # initial
REV 1021 | param=threshold_8 | value=16 | supersedes=1020 | status=active   # revised
REV 1022 | param=threshold_9 | value=9 | supersedes=none | status=active   # initial
REV 1023 | param=threshold_9 | value=18 | supersedes=1022 | status=active   # revised
REV 1024 | param=threshold_9 | value=999 | supersedes=1023 | status=revoked   # rolled back
REV 1025 | param=threshold_10 | value=10 | supersedes=none | status=active   # initial
REV 1026 | param=threshold_10 | value=20 | supersedes=1025 | status=active   # revised
REV 1027 | param=threshold_11 | value=11 | supersedes=none | status=active   # initial
REV 1028 | param=threshold_11 | value=22 | supersedes=1027 | status=active   # revised
REV 1029 | param=threshold_12 | value=12 | supersedes=none | status=active   # initial
REV 1030 | param=threshold_12 | value=24 | supersedes=1029 | status=active   # revised
REV 1031 | param=threshold_12 | value=999 | supersedes=1030 | status=revoked   # rolled back
REV 1032 | param=points_multiplier | value=7 | supersedes=none | status=active   # initial coefficient
REV 1033 | param=threshold_13 | value=13 | supersedes=none | status=active   # initial
REV 1034 | param=threshold_13 | value=26 | supersedes=1033 | status=active   # revised
REV 1035 | param=threshold_14 | value=14 | supersedes=none | status=active   # initial
REV 1036 | param=threshold_14 | value=28 | supersedes=1035 | status=active   # revised
REV 1037 | param=threshold_15 | value=15 | supersedes=none | status=active   # initial
REV 1038 | param=threshold_15 | value=30 | supersedes=1037 | status=active   # revised
REV 1039 | param=threshold_15 | value=999 | supersedes=1038 | status=revoked   # rolled back
REV 1040 | param=threshold_16 | value=16 | supersedes=none | status=active   # initial
REV 1041 | param=threshold_16 | value=32 | supersedes=1040 | status=active   # revised
REV 1042 | param=threshold_17 | value=17 | supersedes=none | status=active   # initial
REV 1043 | param=threshold_17 | value=34 | supersedes=1042 | status=active   # revised
REV 1044 | param=threshold_18 | value=18 | supersedes=none | status=active   # initial
REV 1045 | param=threshold_18 | value=36 | supersedes=1044 | status=active   # revised
REV 1046 | param=threshold_18 | value=999 | supersedes=1045 | status=revoked   # rolled back
REV 1047 | param=digest_salt | value=SEED-1 | supersedes=none | status=active   # placeholder salt
REV 1048 | param=threshold_19 | value=19 | supersedes=none | status=active   # initial
REV 1049 | param=threshold_19 | value=38 | supersedes=1048 | status=active   # revised
REV 1050 | param=threshold_20 | value=20 | supersedes=none | status=active   # initial
REV 1051 | param=threshold_20 | value=40 | supersedes=1050 | status=active   # revised
REV 1052 | param=threshold_21 | value=21 | supersedes=none | status=active   # initial
REV 1053 | param=threshold_21 | value=42 | supersedes=1052 | status=active   # revised
REV 1054 | param=threshold_21 | value=999 | supersedes=1053 | status=revoked   # rolled back
REV 1055 | param=threshold_22 | value=22 | supersedes=none | status=active   # initial
REV 1056 | param=threshold_22 | value=44 | supersedes=1055 | status=active   # revised
REV 1057 | param=threshold_23 | value=23 | supersedes=none | status=active   # initial
REV 1058 | param=threshold_23 | value=46 | supersedes=1057 | status=active   # revised
REV 1059 | param=threshold_24 | value=24 | supersedes=none | status=active   # initial
REV 1060 | param=threshold_24 | value=48 | supersedes=1059 | status=active   # revised
REV 1061 | param=threshold_24 | value=999 | supersedes=1060 | status=revoked   # rolled back
REV 1062 | param=threshold_25 | value=25 | supersedes=none | status=active   # initial
REV 1063 | param=threshold_25 | value=50 | supersedes=1062 | status=active   # revised
REV 1064 | param=threshold_26 | value=26 | supersedes=none | status=active   # initial
REV 1065 | param=threshold_26 | value=52 | supersedes=1064 | status=active   # revised
REV 1066 | param=threshold_27 | value=27 | supersedes=none | status=active   # initial
REV 1067 | param=threshold_27 | value=54 | supersedes=1066 | status=active   # revised
REV 1068 | param=threshold_27 | value=999 | supersedes=1067 | status=revoked   # rolled back
REV 1069 | param=points_multiplier | value=11 | supersedes=1032 | status=active   # raised after review
REV 1070 | param=threshold_28 | value=28 | supersedes=none | status=active   # initial
REV 1071 | param=threshold_28 | value=56 | supersedes=1070 | status=active   # revised
REV 1072 | param=threshold_29 | value=29 | supersedes=none | status=active   # initial
REV 1073 | param=threshold_29 | value=58 | supersedes=1072 | status=active   # revised
REV 1074 | param=threshold_30 | value=30 | supersedes=none | status=active   # initial
REV 1075 | param=threshold_30 | value=60 | supersedes=1074 | status=active   # revised
REV 1076 | param=threshold_30 | value=999 | supersedes=1075 | status=revoked   # rolled back
REV 1077 | param=threshold_31 | value=31 | supersedes=none | status=active   # initial
REV 1078 | param=threshold_31 | value=62 | supersedes=1077 | status=active   # revised
REV 1079 | param=threshold_32 | value=32 | supersedes=none | status=active   # initial
REV 1080 | param=threshold_32 | value=64 | supersedes=1079 | status=active   # revised
REV 1081 | param=threshold_33 | value=33 | supersedes=none | status=active   # initial
REV 1082 | param=threshold_33 | value=66 | supersedes=1081 | status=active   # revised
REV 1083 | param=threshold_33 | value=999 | supersedes=1082 | status=revoked   # rolled back
REV 1084 | param=points_multiplier | value=99 | supersedes=1069 | status=revoked   # proposed but rejected — do not use
REV 1085 | param=threshold_34 | value=34 | supersedes=none | status=active   # initial
REV 1086 | param=threshold_34 | value=68 | supersedes=1085 | status=active   # revised
REV 1087 | param=threshold_35 | value=35 | supersedes=none | status=active   # initial
REV 1088 | param=threshold_35 | value=70 | supersedes=1087 | status=active   # revised
REV 1089 | param=threshold_36 | value=36 | supersedes=none | status=active   # initial
REV 1090 | param=threshold_36 | value=72 | supersedes=1089 | status=active   # revised
REV 1091 | param=threshold_36 | value=999 | supersedes=1090 | status=revoked   # rolled back
REV 1092 | param=threshold_37 | value=37 | supersedes=none | status=active   # initial
REV 1093 | param=threshold_37 | value=74 | supersedes=1092 | status=active   # revised
REV 1094 | param=threshold_38 | value=38 | supersedes=none | status=active   # initial
REV 1095 | param=threshold_38 | value=76 | supersedes=1094 | status=active   # revised
REV 1096 | param=threshold_39 | value=39 | supersedes=none | status=active   # initial
REV 1097 | param=threshold_39 | value=78 | supersedes=1096 | status=active   # revised
REV 1098 | param=threshold_39 | value=999 | supersedes=1097 | status=revoked   # rolled back
REV 1099 | param=legacy_flag_0 | value=40 | supersedes=none | status=active   # initial
REV 1100 | param=legacy_flag_0 | value=80 | supersedes=1099 | status=active   # revised
REV 1101 | param=legacy_flag_1 | value=41 | supersedes=none | status=active   # initial
REV 1102 | param=legacy_flag_1 | value=82 | supersedes=1101 | status=active   # revised
REV 1103 | param=legacy_flag_2 | value=42 | supersedes=none | status=active   # initial
REV 1104 | param=legacy_flag_2 | value=84 | supersedes=1103 | status=active   # revised
REV 1105 | param=legacy_flag_2 | value=999 | supersedes=1104 | status=revoked   # rolled back
REV 1106 | param=legacy_flag_3 | value=43 | supersedes=none | status=active   # initial
REV 1107 | param=legacy_flag_3 | value=86 | supersedes=1106 | status=active   # revised
REV 1108 | param=legacy_flag_4 | value=44 | supersedes=none | status=active   # initial
REV 1109 | param=legacy_flag_4 | value=88 | supersedes=1108 | status=active   # revised
REV 1110 | param=digest_salt | value=FORGE-9.5 | supersedes=1047 | status=active   # final salt for release
REV 1111 | param=legacy_flag_5 | value=45 | supersedes=none | status=active   # initial
REV 1112 | param=legacy_flag_5 | value=90 | supersedes=1111 | status=active   # revised
REV 1113 | param=legacy_flag_5 | value=999 | supersedes=1112 | status=revoked   # rolled back
REV 1114 | param=legacy_flag_6 | value=46 | supersedes=none | status=active   # initial
REV 1115 | param=legacy_flag_6 | value=92 | supersedes=1114 | status=active   # revised
REV 1116 | param=legacy_flag_7 | value=47 | supersedes=none | status=active   # initial
REV 1117 | param=legacy_flag_7 | value=94 | supersedes=1116 | status=active   # revised
REV 1118 | param=legacy_flag_8 | value=48 | supersedes=none | status=active   # initial
REV 1119 | param=legacy_flag_8 | value=96 | supersedes=1118 | status=active   # revised
REV 1120 | param=legacy_flag_8 | value=999 | supersedes=1119 | status=revoked   # rolled back
REV 1121 | param=legacy_flag_9 | value=49 | supersedes=none | status=active   # initial
REV 1122 | param=legacy_flag_9 | value=98 | supersedes=1121 | status=active   # revised
REV 1123 | param=legacy_flag_10 | value=50 | supersedes=none | status=active   # initial
REV 1124 | param=legacy_flag_10 | value=100 | supersedes=1123 | status=active   # revised
REV 1125 | param=legacy_flag_11 | value=51 | supersedes=none | status=active   # initial
REV 1126 | param=legacy_flag_11 | value=102 | supersedes=1125 | status=active   # revised
REV 1127 | param=legacy_flag_11 | value=999 | supersedes=1126 | status=revoked   # rolled back
REV 1128 | param=digest_salt | value=BOGUS-X | supersedes=1110 | status=revoked   # leaked, revoked
REV 1129 | param=legacy_flag_12 | value=52 | supersedes=none | status=active   # initial
REV 1130 | param=legacy_flag_12 | value=104 | supersedes=1129 | status=active   # revised
REV 1131 | param=legacy_flag_13 | value=53 | supersedes=none | status=active   # initial
REV 1132 | param=legacy_flag_13 | value=106 | supersedes=1131 | status=active   # revised
REV 1133 | param=legacy_flag_14 | value=54 | supersedes=none | status=active   # initial
REV 1134 | param=legacy_flag_14 | value=108 | supersedes=1133 | status=active   # revised
REV 1135 | param=legacy_flag_14 | value=999 | supersedes=1134 | status=revoked   # rolled back
REV 1136 | param=legacy_flag_15 | value=55 | supersedes=none | status=active   # initial
REV 1137 | param=legacy_flag_15 | value=110 | supersedes=1136 | status=active   # revised
REV 1138 | param=legacy_flag_16 | value=56 | supersedes=none | status=active   # initial
REV 1139 | param=legacy_flag_16 | value=112 | supersedes=1138 | status=active   # revised
REV 1140 | param=legacy_flag_17 | value=57 | supersedes=none | status=active   # initial
REV 1141 | param=legacy_flag_17 | value=114 | supersedes=1140 | status=active   # revised
REV 1142 | param=legacy_flag_17 | value=999 | supersedes=1141 | status=revoked   # rolled back
REV 1143 | param=legacy_flag_18 | value=58 | supersedes=none | status=active   # initial
REV 1144 | param=legacy_flag_18 | value=116 | supersedes=1143 | status=active   # revised
REV 1145 | param=legacy_flag_19 | value=59 | supersedes=none | status=active   # initial
REV 1146 | param=legacy_flag_19 | value=118 | supersedes=1145 | status=active   # revised
REV 1147 | param=legacy_flag_20 | value=60 | supersedes=none | status=active   # initial
REV 1148 | param=legacy_flag_20 | value=120 | supersedes=1147 | status=active   # revised
REV 1149 | param=legacy_flag_20 | value=999 | supersedes=1148 | status=revoked   # rolled back
REV 1150 | param=legacy_flag_21 | value=61 | supersedes=none | status=active   # initial
REV 1151 | param=legacy_flag_21 | value=122 | supersedes=1150 | status=active   # revised
REV 1152 | param=legacy_flag_22 | value=62 | supersedes=none | status=active   # initial
REV 1153 | param=legacy_flag_22 | value=124 | supersedes=1152 | status=active   # revised
REV 1154 | param=legacy_flag_23 | value=63 | supersedes=none | status=active   # initial
REV 1155 | param=legacy_flag_23 | value=126 | supersedes=1154 | status=active   # revised
REV 1156 | param=legacy_flag_23 | value=999 | supersedes=1155 | status=revoked   # rolled back
REV 1157 | param=legacy_flag_24 | value=64 | supersedes=none | status=active   # initial
REV 1158 | param=legacy_flag_24 | value=128 | supersedes=1157 | status=active   # revised
REV 1159 | param=legacy_flag_25 | value=65 | supersedes=none | status=active   # initial
REV 1160 | param=legacy_flag_25 | value=130 | supersedes=1159 | status=active   # revised
REV 1161 | param=legacy_flag_26 | value=66 | supersedes=none | status=active   # initial
REV 1162 | param=legacy_flag_26 | value=132 | supersedes=1161 | status=active   # revised
REV 1163 | param=legacy_flag_26 | value=999 | supersedes=1162 | status=revoked   # rolled back
REV 1164 | param=legacy_flag_27 | value=67 | supersedes=none | status=active   # initial
REV 1165 | param=legacy_flag_27 | value=134 | supersedes=1164 | status=active   # revised
REV 1166 | param=legacy_flag_28 | value=68 | supersedes=none | status=active   # initial
REV 1167 | param=legacy_flag_28 | value=136 | supersedes=1166 | status=active   # revised
REV 1168 | param=legacy_flag_29 | value=69 | supersedes=none | status=active   # initial
REV 1169 | param=legacy_flag_29 | value=138 | supersedes=1168 | status=active   # revised
REV 1170 | param=legacy_flag_29 | value=999 | supersedes=1169 | status=revoked   # rolled back
REV 1171 | param=legacy_flag_30 | value=70 | supersedes=none | status=active   # initial
REV 1172 | param=legacy_flag_30 | value=140 | supersedes=1171 | status=active   # revised
REV 1173 | param=legacy_flag_31 | value=71 | supersedes=none | status=active   # initial
REV 1174 | param=legacy_flag_31 | value=142 | supersedes=1173 | status=active   # revised
REV 1175 | param=legacy_flag_32 | value=72 | supersedes=none | status=active   # initial
REV 1176 | param=legacy_flag_32 | value=144 | supersedes=1175 | status=active   # revised
REV 1177 | param=legacy_flag_32 | value=999 | supersedes=1176 | status=revoked   # rolled back
REV 1178 | param=legacy_flag_33 | value=73 | supersedes=none | status=active   # initial
REV 1179 | param=legacy_flag_33 | value=146 | supersedes=1178 | status=active   # revised
REV 1180 | param=legacy_flag_34 | value=74 | supersedes=none | status=active   # initial
REV 1181 | param=legacy_flag_34 | value=148 | supersedes=1180 | status=active   # revised
REV 1182 | param=legacy_flag_35 | value=75 | supersedes=none | status=active   # initial
REV 1183 | param=legacy_flag_35 | value=150 | supersedes=1182 | status=active   # revised
REV 1184 | param=legacy_flag_35 | value=999 | supersedes=1183 | status=revoked   # rolled back
REV 1185 | param=legacy_flag_36 | value=76 | supersedes=none | status=active   # initial
REV 1186 | param=legacy_flag_36 | value=152 | supersedes=1185 | status=active   # revised
REV 1187 | param=legacy_flag_37 | value=77 | supersedes=none | status=active   # initial
REV 1188 | param=legacy_flag_37 | value=154 | supersedes=1187 | status=active   # revised
REV 1189 | param=legacy_flag_38 | value=78 | supersedes=none | status=active   # initial
REV 1190 | param=legacy_flag_38 | value=156 | supersedes=1189 | status=active   # revised
REV 1191 | param=legacy_flag_38 | value=999 | supersedes=1190 | status=revoked   # rolled back
REV 1192 | param=legacy_flag_39 | value=79 | supersedes=none | status=active   # initial
REV 1193 | param=legacy_flag_39 | value=158 | supersedes=1192 | status=active   # revised
