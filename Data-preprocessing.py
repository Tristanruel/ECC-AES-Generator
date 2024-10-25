import pandas as pd

user_response = input("Does the data need processing? (yes/no): ")

yes = {'yes', 'y', 'YES', 'Yes', 'yEs', 'yeS'}

if user_response.lower() in yes:
    file_path = 'Radiation Data/20241024_23_01_35.csv'
    data = pd.read_csv(file_path, header=None)
    data.iloc[:, 3] = pd.to_numeric(data.iloc[:, 3], errors='coerce')
    data = data[~data.iloc[:, 3].between(0, 1000, inclusive='both')]
    data = data.iloc[:, 4:]
    data = data.iloc[3:]
    data.to_csv(file_path, index=False, header=False)

    print("Rows with 4th column values between 0 and 1000 removed, and first 4 columns and first 3 rows have been removed successfully.")
else:
    print("Ok")
