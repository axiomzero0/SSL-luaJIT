-- escape-time float kernel: 100x100 grid, max 250 iterations per point
local total = 0
for py = 0, 99 do
  for px = 0, 99 do
    local x = 0.0
    local y = 0.0
    local n = 0
    while x * x + y * y <= 4.0 and n < 250 do
      local xt = x * x - y * y + (px * 0.02 - 1.0)
      y = 2.0 * x * y + (py * 0.02 - 1.0)
      x = xt
      n = n + 1
    end
    total = total + n
  end
end
print(total)
