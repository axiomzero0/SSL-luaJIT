-- math builtin calls: sin and sqrt over 200,000 iterations
-- NOTE: SSL-LuaJIT uses deterministic polynomial sin and Newton sqrt, so the
-- printed value differs slightly from LuaJIT's libm-backed result by design.
local s = 0.0
for i = 1, 200000 do
  s = s + math.sin(i) + math.sqrt(i)
end
print(s)
