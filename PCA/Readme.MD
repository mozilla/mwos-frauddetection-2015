
## Method

We will try to use Principal Component Analysis on the data we have to see the variance we have in it.
About PCA

> It is often useful to measure data in terms of its principal components rather than on a normal x-y axis. So what are principal components then? They’re the underlying structure in the data. They are the directions where there is the most variance, the directions where the data is most spread out

### Preparing the logs

PCA normally only takes numeric input, and some of these columns contain alphanumeric data. So we now need to convert all data to numbers only. A really simple way of doing this is just to convert each cell to it’s ASCII equivalent. So “abc” would be 97+98+99=294

A simple python script is written that iterates through the CSV file and converts everything to the decimal ASCII equivalent. The script takes as an input a file called “output1.csv” and outputs to a file called “papagena.csv”, and it assumes the first row contains column names so it leaves them untouched.

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

### Tool Used:

RapidMiner

### PCA

![enter image description here](https://raw.githubusercontent.com/mozilla/mwos-frauddetection-2015/experiment/PCA/PCA.PNG)

In the above we note that PC1 and PC2 has the maximum variation among these all.
We next see what components these two map with

![enter image description here](https://raw.githubusercontent.com/mozilla/mwos-frauddetection-2015/experiment/PCA/PCA_EigenVector.PNG)

Here we see PC1 and PC2 is most influenced by Date and User and PC4 by IP address.
Just trying to visualize it in a scatter plot gives us something like this

![enter image description here](https://raw.githubusercontent.com/mozilla/mwos-frauddetection-2015/experiment/PCA/PCA_ID.PNG)
