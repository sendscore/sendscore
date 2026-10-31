//go:build race

package engine

// raceFactor widens time limits in tests, since the race detector slows code
// several times over on a busy CI machine.
const raceFactor = 4
