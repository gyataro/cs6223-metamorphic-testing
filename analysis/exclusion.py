import pandas as pd

df = pd.read_csv("rq2.csv")

result = df.groupby(['round', 'exclusion'], as_index=False).agg(
    new_value=('alert', lambda x: not x.all())  # True if any 'alert' is False
)

result = result.groupby("round", as_index=False).agg(
    caught=('new_value', lambda x: x.sum())
)

print(result)