package es.dpc;

public class Test implements TestMXBean {
	private int val;

	/* (non-Javadoc)
	 * @see es.dpc.TestMBean#getVal()
	 */
	@Override
	public int getVal() {
		return val;
	}

	/* (non-Javadoc)
	 * @see es.dpc.TestMBean#setVal(int)
	 */
	@Override
	public void setVal(int val) {
		this.val = val;
	}
	
	/* (non-Javadoc)
	 * @see es.dpc.TestMBean#doSomething()
	 */
	@Override
	public int doSomething(){
		return ++val;
	}
}
