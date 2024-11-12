import pandas as pd
from scipy import stats

# Load CSV files
df = pd.read_csv('entries.csv')
df = df.groupby('round').filter(lambda group: group['alert'].all() and (group['time'] >= 0).all())

# Filter the DataFrame based on the label column
before = df[df['label'] == 'r']
after = df[df['label'] == "r'"] 

# Perform the paired sample t-test
t_stat, p_value = stats.ttest_rel(before["time"], after["time"])

# Print the results
print(f"T-statistic: {t_stat}")
print(f"P-value: {p_value}")

# Interpret the result
alpha = 0.05  # significance level
if p_value < alpha:
    print("Reject the null hypothesis: there is a significant difference.")
else:
    print("Fail to reject the null hypothesis: no significant difference.")