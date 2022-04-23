import { FslAssertionExpectation } from '../type';
import FslValidationError from '../error/validationError';

class AssertionExpectationBuilder {
  expectation: FslAssertionExpectation;

  constructor(expectation: FslAssertionExpectation) {
    this.expectation = { ...expectation };
  }

  validate(): boolean {
    const errorMessages: string[] = [];

    if (errorMessages.length > 0) {
      throw new FslValidationError(errorMessages.join(' & '));
    }

    return true;
  }

  build(): FslAssertionExpectation {
    this.validate();

    return { ...this.expectation };
  }
}

export default AssertionExpectationBuilder;
