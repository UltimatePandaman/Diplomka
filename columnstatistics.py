import pandas as pd
import sys
import json

#Výstupní soubory. errors='ignore' je klíčové
fstats = open('column_statistics.in', 'r', encoding='utf16', errors='ignore')

lines = fstats.readlines()
counts = lines[0::3]
#uniques = lines[1::3]
names = lines[2::3]

unsortedCounts = {}
for index in range(len(names)):
    unsortedCounts[names[index][0:-1]] = int(counts[index])

sortedCounts = dict(sorted(unsortedCounts.items(), key=lambda x: x[1]))

for record in sortedCounts:
    print("{0}: {1}".format(record, sortedCounts[record]))