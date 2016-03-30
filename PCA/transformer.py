import csv

with open('papagena.csv', 'w') as outfile:
    c = csv.writer(outfile)
    counter = 0
    with open('output1.csv','rb') as f:
        for row in csv.reader(f, delimiter=','):
            counter = counter + 1
            mod_row = []
            if counter != 1:
                for cell in row:
                    mod_row.append(sum(bytearray(cell)))
                else:
                        for cell in row:
                            mod_row.append(cell)
                c.writerow(mod_row)
print "processed {} rows".format(counter)
