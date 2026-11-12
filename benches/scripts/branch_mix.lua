-- branchy loop with a data-dependent condition: 3,000,000 iterations
local s = 0
for i = 1, 3000000 do
  if s > 100 then
    s = s - 1
  else
    s = s + 3
  end
end
print(s)
