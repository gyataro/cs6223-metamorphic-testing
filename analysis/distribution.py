import pandas as pd
import seaborn as sns
import matplotlib
import matplotlib.pyplot as plt

sns.set_theme(style="white")
matplotlib.rcParams['font.family'] = 'DejaVu Sans'   # Change to the font you prefer
matplotlib.rcParams['font.size'] = 12          # Adjust font size globally

# Load CSV files
df = pd.read_csv('entries.csv')
df = df[df["alert"] == True]

# Filter the DataFrame based on the label column
df1 = df[df['label'] == 'r']
df2 = df[df['label'] == "r'"] 

# Plot the distribution of the columns
fig, (ax, ax2) = plt.subplots(1, 2, sharex=False, sharey=True, facecolor='w')

# Plot the histogram (bin plot) for df1 (label 'r')
sns.histplot(df1["time"], ax=ax, bins=25, kde=False, label=f'rule r', color='blue', binrange=[0, 0.1])
sns.histplot(df2["time"], ax=ax, bins=25, kde=False, label=f"rule r'", color='red', binrange=[0, 0.1])
sns.histplot(df2["time"], ax=ax2, bins=25, kde=False, label=f"rule r'", color='red', binrange=[1, 8])

# Plot the histogram (bin plot) for df2 (label r')
#sns.histplot(df2, bins=5, kde=False, label=f'(label r\')', color='red', stat='density')
ax.set_xlim(0, 0.1)
ax2.set_xlim(1, 8)

# hide the spines between ax and ax2
ax.spines['right'].set_visible(False)
ax2.spines['left'].set_visible(False)
ax.tick_params(labelright='off')
ax.yaxis.tick_left()
ax2.yaxis.tick_right()

# Show legend
ax.legend(title='Legend', loc='upper right', fontsize=10)

# Add labels and title
fig.suptitle("Distribution of time for r and r'", fontsize=16)
fig.supxlabel("Time taken (seconds)")
fig.supylabel("Frequency")
ax.set_xlabel('')
ax.set_ylabel('')
ax2.set_xlabel('')
ax2.set_ylabel('')
#plt.setp(plt.gcf().get_axes(), yticks=[])
#ax2.set_yticks([]) 
#ax2.set_yticklabels([])

# This looks pretty good, and was fairly painless, but you can get that
# cut-out diagonal lines look with just a bit more work. The important
# thing to know here is that in axes coordinates, which are always
# between 0-1, spine endpoints are at these locations (0, 0), (0, 1),
# (1, 0), and (1, 1).  Thus, we just need to put the diagonals in the
# appropriate corners of each of our axes, and so long as we use the
# right transform and disable clipping.

d = .015  # how big to make the diagonal lines in axes coordinates
# arguments to pass plot, just so we don't keep repeating them
kwargs = dict(transform=ax.transAxes, color='k', clip_on=False)
ax.plot((1-d, 1+d), (-d, +d), **kwargs)
ax.plot((1-d, 1+d), (1-d, 1+d), **kwargs)

kwargs.update(transform=ax2.transAxes)  # switch to the bottom axes
ax2.plot((-d, +d), (1-d, 1+d), **kwargs)
ax2.plot((-d, +d), (-d, +d), **kwargs)

# Save the plot as a PDF
plt.savefig('distribution_plot.pdf', format='pdf')
plt.savefig('distribution_plot.png', format='png')