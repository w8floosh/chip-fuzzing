import argparse
import matplotlib.pyplot as plt
import matplotlib.patches as patches
import numpy as np
import yaml
from matplotlib.colors import LogNorm

# Set up argument parser
parser = argparse.ArgumentParser(description="Generate a heatmap from YAML data.")
parser.add_argument("yaml_file", type=str, help="Path to the YAML file containing observation data.")
args = parser.parse_args()

# Load data from the specified YAML file
with open(args.yaml_file, "r") as file:
    data = yaml.safe_load(file)

# Process data to extract counts
data_counts = {}
error_codes = set()
endpoints_clusters = set()
commands_per_cluster = {}

# Extract data
for entry in data['observationStats']:
    endpoint = hex(entry['path']['endpoint'])
    cluster = hex(entry['path']['cluster'])
    command = hex(entry['path']['command'])
    error_code = hex(entry['statusResponse'])
    times = entry['times']

    # Record the count for (endpoint, cluster, command, error_code)
    key = (endpoint, cluster, command, error_code)
    data_counts[key] = data_counts.get(key, 0) + times

    # Update unique sets for rows and columns
    error_codes.add(error_code)
    endpoints_clusters.add((endpoint, cluster))

    # Populate commands for each cluster
    if cluster not in commands_per_cluster:
        commands_per_cluster[cluster] = set()
    commands_per_cluster[cluster].add(command)

# Convert sets to sorted lists for consistent order
error_codes = sorted(error_codes)
endpoints_clusters = sorted(endpoints_clusters, key=lambda x: (x[0], x[1]))
commands_per_cluster = {k: sorted(v, key=lambda x: int(x, 16)) for k, v in commands_per_cluster.items()}

# Heatmap Construction
fig, ax = plt.subplots(figsize=(12, 8))

# Parameters
cell_size = 1  # Size of each big cell

# Normalize counts for logarithmic scale
all_counts = list(data_counts.values())
norm = LogNorm(vmin=1, vmax=max(all_counts))  # Ensure vmin > 0 for LogNorm
# Use a colorful colormap
cmap = plt.cm.viridis  # Change to a color colormap

# Loop through each big cell (row: endpoint, cluster; column: error code)
for row_idx, (endpoint, cluster) in enumerate(endpoints_clusters):
    num_cmds = len(commands_per_cluster[cluster])
    subcell_grid = int(np.ceil(np.sqrt(num_cmds)))  # Calculate grid size for subcells
    subcell_side = cell_size / subcell_grid        # Uniform size for each subcell

    for col_idx, error in enumerate(error_codes):
        # Starting position of the big cell
        x_start = col_idx * cell_size
        y_start = row_idx * cell_size

        # Loop through all positions in the subcell grid
        for subcell_row in range(subcell_grid):
            for subcell_col in range(subcell_grid):
                # Calculate subcell position
                sub_x = x_start + subcell_col * subcell_side
                sub_y = y_start + subcell_row * subcell_side
                width = subcell_side
                height = subcell_side

                # Determine if this subcell corresponds to a command
                cmd_idx = subcell_row * subcell_grid + subcell_col
                if cmd_idx < num_cmds:  # Valid command index
                    cmd = commands_per_cluster[cluster][cmd_idx]
                    count = data_counts.get((endpoint, cluster, cmd, error), 0)

                    # Get color for non-empty cells
                    color = cmap(norm(count))

                    # Draw rectangle for subcell with color
                    rect = patches.Rectangle(
                        (sub_x, sub_y),
                        width,
                        height,
                        linewidth=0.5,
                        edgecolor='black',
                        facecolor=color,
                        hatch=None
                    )
                    ax.add_patch(rect)

                    # Add text for the command ID
                    ax.text(
                        sub_x + width / 2,
                        sub_y + height / 2,
                        cmd,
                        color="white" if norm(count) < 0.5 else "black",
                        ha="center",
                        va="center",
                        fontsize=24//subcell_grid
                    )
                else:  # Unused subcell (fill with pattern)
                    rect = patches.Rectangle(
                        (sub_x, sub_y),
                        width,
                        height,
                        linewidth=0.5,
                        edgecolor='black',
                        facecolor='white',
                        hatch='///'  # Police line texture
                    )
                    ax.add_patch(rect)

        # Add thicker border around the big cell
        ax.add_patch(patches.Rectangle(
            (x_start, y_start),
            cell_size,
            cell_size,
            linewidth=2,
            edgecolor='black',
            facecolor='none'
        ))


# Set the axis limits to fit the data exactly
ax.set_xlim(0, len(error_codes) * cell_size)
ax.set_ylim(0, len(endpoints_clusters) * cell_size)

# Remove extra empty space by disabling the automatic extension of the axis
ax.set_aspect('equal', adjustable='box')  # Prevent stretching
ax.set_xlabel('Error codes')
ax.set_ylabel('(Endpoint, Cluster) pairs')
# Set ticks and labels
ax.set_xticks([cell_size * i + cell_size / 2 for i in range(len(error_codes))])
ax.set_yticks([cell_size * i + cell_size / 2 for i in range(len(endpoints_clusters))])
ax.set_xticklabels(error_codes, rotation=45, ha='right', fontsize=8)
ax.set_yticklabels([f"{ep}, {cl}" for (ep, cl) in endpoints_clusters], fontsize=8)

# Remove any duplicate ticks or misplaced grids
ax.tick_params(which='minor', bottom=False, left=False)
ax.grid(which='minor', color='black', linestyle='-', linewidth=1)

# Add colorbar
sm = plt.cm.ScalarMappable(cmap=cmap, norm=norm)
sm.set_array([])
cbar = plt.colorbar(sm, ax=ax, fraction=0.046, pad=0.04)
cbar.set_label('Number of observations (log scale)')

# Add a title
plt.title('Meross Smart Plug MSS315 observation heatmap - test #3')

# Adjust layout
plt.tight_layout()

# Save the figure locally
output_file = "meross_heatmap_3.png"
plt.savefig(output_file, dpi=300, bbox_inches='tight')
print(f"Heatmap saved to {output_file}")

# Display the plot
plt.show()

# Extract data for the second heatmap
test_stats = data.get('testStats', {})
error_data = test_stats.get('errors', [])
error_codes = [hex(entry['code']) for entry in error_data]  # Ensure hexadecimal representation
x_labels = ["expected", "unexpected"]

# Prepare the heatmap data
heatmap_data = []
for entry in error_data:
    row = [entry['expected'], entry['unexpected']]
    heatmap_data.append(row)

heatmap_data = np.array(heatmap_data)

# Create a new heatmap
fig, ax = plt.subplots(figsize=(6, 6))

# Normalize counts for better visualization
norm = LogNorm(vmin=max(1, heatmap_data.min()), vmax=heatmap_data.max())
cmap = plt.cm.viridis

# Plot the heatmap
im = ax.imshow(heatmap_data, cmap=cmap, norm=norm)

# Add color bar
cbar = plt.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
cbar.set_label("Count")

# Set axis labels and ticks
ax.set_xticks(range(len(x_labels)))
ax.set_yticks(range(len(error_codes)))
ax.set_xticklabels(x_labels, fontsize=10)
ax.set_yticklabels(error_codes, fontsize=10)
ax.set_ylabel("Error code")
# Add data annotations to the cells
for i in range(len(error_codes)):
    for j in range(len(x_labels)):
        count = heatmap_data[i, j]
        ax.text(
            j, i, f"{count:,}",
            ha="center", va="center",
            color="black" if norm(count) > 0.5 or count == 0 else "white",
            fontsize=14
        )

# Add a title
plt.title("Meross Smart Plug MSS315 bug oracle heatmap - test #3")

# Adjust layout
plt.tight_layout()

# Save and show the new heatmap
output_file = "meross_oracle_heatmap_3.png"
plt.savefig(output_file, dpi=300, bbox_inches='tight')
print(f"Test stats heatmap saved to {output_file}")
plt.show()
