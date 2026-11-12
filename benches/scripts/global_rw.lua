-- global variable read/write traffic: 3,000,000 iterations
g = 0
for i = 1, 3000000 do
  g = g + 1
end
print(g)
