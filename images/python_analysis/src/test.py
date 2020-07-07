if __name__ == '__main__':
    transactions = {0: {"CPU Overload": 0, "ca": 0}}

    thisdict = {"brand": "Ford", "model": "Mustang", "year": 1964, "color": "red"}

    transactions[0]['test'] = 1

    transactions[1] = {"": 0}
    transactions[1]['test2'] = 2


    for k, v in transactions[0].items():
        if k in ["salut", "ca", "va"]:
            transactions[0][k] = 1

    print(thisdict)
    print(transactions)
